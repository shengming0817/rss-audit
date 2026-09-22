use crate::{AdmissionViolation as Violation, Error, MIGRATION_SQL};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};

fn require(valid: bool, category: Violation) -> Result<(), Error> {
    if valid {
        Ok(())
    } else {
        Err(Error::Admission(category))
    }
}

pub(crate) async fn tenant(connection: &mut PgConnection, expected: TenantId) -> Result<(), Error> {
    let setting: Option<String> =
        sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)")
            .fetch_one(&mut *connection)
            .await?;
    if setting.as_deref().and_then(|s| TenantId::parse(s).ok()) != Some(expected) {
        return Err(Error::ScopeMismatch);
    }
    validate(connection).await
}

pub(crate) async fn validate(connection: &mut PgConnection) -> Result<(), Error> {
    roles(connection).await?;
    relations(connection).await?;
    columns(connection).await?;
    constraints(connection).await?;
    policies(connection).await?;
    functions(connection).await?;
    privileges(connection).await
}

async fn roles(c: &mut PgConnection) -> Result<(), Error> {
    let safe: bool = sqlx::query_scalar(
        r#"
SELECT session_user = current_user
 AND EXISTS (SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner
   WHERE n.nspname='rss_audit' AND NOT r.rolcanlogin AND NOT r.rolsuper
     AND NOT r.rolbypassrls AND NOT r.rolcreaterole
     AND NOT pg_has_role(current_user,r.oid,'SET'))
 AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'SET')
   AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb))
 AND NOT EXISTS (SELECT 1 FROM pg_namespace n, pg_roles r
   WHERE n.nspname='rss_audit' AND pg_has_role(current_user,r.oid,'SET')
     AND has_schema_privilege(r.oid,n.oid,'CREATE'))
 AND NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member
   WHERE m.admin_option AND pg_has_role(current_user,r.oid,'SET'))
"#,
    )
    .fetch_one(c)
    .await?;
    require(safe, Violation::Role)
}

async fn relations(c: &mut PgConnection) -> Result<(), Error> {
    let rows = sqlx::query(
        r#"SELECT c.relname, c.relkind::text kind, c.relpersistence::text persistence,
 c.relowner=n.nspowner AS owned, c.relrowsecurity AND c.relforcerowsecurity AS rls,
 c.relispartition OR c.relhassubclass AS partitioned,
 EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal) AS triggered,
 EXISTS (SELECT 1 FROM pg_rewrite w WHERE w.ev_class=c.oid) AS rewritten
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_audit' AND c.relkind NOT IN ('i','I') ORDER BY c.relname"#,
    )
    .fetch_all(&mut *c)
    .await?;
    require(rows.len() == 2, Violation::Schema)?;
    for (row, expected) in rows.iter().zip(["heads", "records"]) {
        require(
            row.try_get::<&str, _>("relname")? == expected
                && row.try_get::<&str, _>("kind")? == "r"
                && row.try_get::<&str, _>("persistence")? == "p"
                && row.try_get::<bool, _>("owned")?
                && !row.try_get::<bool, _>("partitioned")?
                && !row.try_get::<bool, _>("triggered")?
                && !row.try_get::<bool, _>("rewritten")?,
            Violation::Schema,
        )?;
        require(row.try_get("rls")?, Violation::Rls)?;
    }
    let valid: bool = sqlx::query_scalar(
        r#"SELECT count(*)=4 AND bool_and(i.indisvalid AND i.indisready
 AND i.indislive AND i.indpred IS NULL AND i.indexprs IS NULL)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_audit'"#,
    )
    .fetch_one(c)
    .await?;
    require(valid, Violation::Shape)
}

async fn columns(c: &mut PgConnection) -> Result<(), Error> {
    let collations:bool=sqlx::query_scalar("SELECT bool_and(a.attcollation=CASE WHEN a.attname IN ('source_id','event_id') THEN 'pg_catalog.\"C\"'::regcollation::oid ELSE 0::oid END) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_audit' AND c.relkind='r' AND a.attnum>0").fetch_one(&mut *c).await?;
    require(collations, Violation::Shape)?;
    let plain:bool=sqlx::query_scalar("SELECT count(*)=9 AND bool_and(NOT a.attisdropped AND NOT a.atthasdef AND a.attidentity='' AND a.attgenerated='') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_audit' AND c.relkind='r' AND a.attnum>0").fetch_one(&mut *c).await?;
    require(plain, Violation::Shape)?;
    let actual: Vec<String> = sqlx::query_scalar(
        r#"SELECT c.relname||':'||a.attname||':'||
 format_type(a.atttypid,a.atttypmod)||':'||a.attnotnull::text
 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_audit' AND c.relkind='r' AND a.attnum>0
 AND NOT a.attisdropped AND NOT a.atthasdef AND a.attidentity='' AND a.attgenerated=''
 ORDER BY c.relname,a.attnum"#,
    )
    .fetch_all(c)
    .await?;
    require(
        actual
            == [
                "heads:tenant_id:uuid:true",
                "heads:position:bigint:false",
                "records:tenant_id:uuid:true",
                "records:source_id:text:true",
                "records:event_id:text:true",
                "records:position:bigint:true",
                "records:recorded_at:bigint:true",
                "records:canonical:bytea:true",
                "records:ledger_sequence:bigint:false",
            ],
        Violation::Shape,
    )
}

async fn constraints(c: &mut PgConnection) -> Result<(), Error> {
    let valid:bool=sqlx::query_scalar("SELECT count(*)=12 AND bool_and(k.convalidated AND NOT k.condeferrable AND NOT k.condeferred) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_audit'").fetch_one(&mut *c).await?;
    require(valid, Violation::Shape)?;
    let mut actual: Vec<String> = sqlx::query_scalar(
        r#"SELECT c.relname||':'||pg_get_constraintdef(k.oid)
 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_audit'
 AND k.convalidated AND NOT k.condeferrable AND NOT k.condeferred"#,
    )
    .fetch_all(c)
    .await?;
    let mut expected = vec![
        "heads:CHECK ((\"position\" >= 0))",
        "heads:PRIMARY KEY (tenant_id)",
        "records:CHECK (((octet_length(source_id) >= 1) AND (octet_length(source_id) <= 64)))",
        "records:CHECK (((octet_length(event_id) >= 1) AND (octet_length(event_id) <= 128)))",
        "records:CHECK ((\"position\" >= 0))",
        "records:CHECK ((recorded_at >= 0))",
        "records:CHECK (((octet_length(canonical) >= 1) AND (octet_length(canonical) <= 131072)))",
        "records:CHECK ((ledger_sequence >= 0))",
        "records:FOREIGN KEY (tenant_id) REFERENCES rss_audit.heads(tenant_id)",
        "records:PRIMARY KEY (tenant_id, source_id, event_id)",
        "records:UNIQUE (tenant_id, \"position\")",
        "records:UNIQUE (tenant_id, ledger_sequence)",
    ];
    actual.sort();
    expected.sort();
    require(actual == expected, Violation::Shape)
}

async fn policies(c: &mut PgConnection) -> Result<(), Error> {
    let rows = sqlx::query(
        r#"SELECT c.relname,p.polname, p.polcmd::text command,p.polpermissive,
 p.polroles=ARRAY[0::oid] AS public,pg_get_expr(p.polqual,p.polrelid) AS using,
 pg_get_expr(p.polwithcheck,p.polrelid) AS checking
 FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_audit' ORDER BY c.relname"#,
    )
    .fetch_all(c)
    .await?;
    require(rows.len() == 2, Violation::Rls)?;
    let expression =
        "(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)";
    for (row, name) in rows.iter().zip(["heads", "records"]) {
        require(
            row.try_get::<&str, _>("relname")? == name
                && row.try_get::<&str, _>("polname")? == "tenant_scope"
                && row.try_get::<&str, _>("command")? == "*"
                && row.try_get::<bool, _>("polpermissive")?
                && row.try_get::<bool, _>("public")?
                && row.try_get::<&str, _>("using")? == expression
                && row.try_get::<&str, _>("checking")? == expression,
            Violation::Rls,
        )?;
    }
    Ok(())
}

async fn functions(c: &mut PgConnection) -> Result<(), Error> {
    let rows = sqlx::query(
        r#"SELECT p.proname,p.prosrc,p.prosecdef,p.proconfig,p.prokind::text kind,
 p.proowner=n.nspowner AS owned,l.lanname,p.provolatile::text volatility,
 pg_get_function_identity_arguments(p.oid) AS arguments,format_type(p.prorettype,NULL) AS result,
 p.proisstrict,p.proleakproof,p.proparallel::text parallel,p.proretset,p.pronargdefaults
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
 WHERE n.nspname='rss_audit' ORDER BY p.proname"#,
    )
    .fetch_all(c)
    .await?;
    require(rows.len() == 2, Violation::Functions)?;
    for (row,(name,args,result)) in rows.iter().zip([
        ("append","p_tenant uuid, p_source text, p_event text, p_recorded bigint, p_canonical bytea, p_ledger bigint","bigint"),
        ("reserve","p_tenant uuid","void")]) {
        let marker=format!("${name}$");
        let body=MIGRATION_SQL.split(&marker).nth(1).ok_or(Error::StorageContract)?;
        require(row.try_get::<&str,_>("proname")?==name && row.try_get::<&str,_>("prosrc")?==body
            && row.try_get::<bool,_>("prosecdef")? && row.try_get::<bool,_>("owned")?
            && row.try_get::<Vec<String>,_>("proconfig")?==["search_path=pg_catalog, rss_audit"]
            && row.try_get::<&str,_>("kind")?=="f" && row.try_get::<&str,_>("lanname")?=="plpgsql"
            && row.try_get::<&str,_>("volatility")?=="v" && row.try_get::<&str,_>("arguments")?==args
            && row.try_get::<&str,_>("result")?==result && !row.try_get::<bool,_>("proisstrict")?
            && !row.try_get::<bool,_>("proleakproof")? && row.try_get::<&str,_>("parallel")?=="u"
            && !row.try_get::<bool,_>("proretset")? && row.try_get::<i16,_>("pronargdefaults")?==0,
            Violation::Functions)?;
    }
    Ok(())
}

async fn privileges(c: &mut PgConnection) -> Result<(), Error> {
    let valid:bool=sqlx::query_scalar(r#"
SELECT has_schema_privilege(current_user,'rss_audit','USAGE')
 AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'SET')
 AND has_schema_privilege(r.oid,'rss_audit','USAGE WITH GRANT OPTION'))
 AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
 pg_roles r WHERE n.nspname='rss_audit' AND c.relkind='r'
 AND pg_has_role(current_user,r.oid,'SET') AND (
 has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')
 OR has_table_privilege(r.oid,c.oid,'SELECT WITH GRANT OPTION')
 OR has_any_column_privilege(r.oid,c.oid,'SELECT WITH GRANT OPTION')))
 AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='rss_audit' AND c.relkind='r' AND NOT has_table_privilege(current_user,c.oid,'SELECT'))
 AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='rss_audit' AND (NOT has_function_privilege(current_user,p.oid,'EXECUTE')
 OR EXISTS (SELECT 1 FROM pg_roles r WHERE pg_has_role(current_user,r.oid,'SET')
 AND has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION'))))
 AND NOT EXISTS (SELECT 1 FROM (
 SELECT a.grantee,a.is_grantable FROM pg_namespace n,
 LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='rss_audit'
 UNION ALL SELECT a.grantee,a.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
 LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='rss_audit'
 UNION ALL SELECT a.grantee,a.is_grantable FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
 LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='rss_audit'
 UNION ALL SELECT acl.grantee,acl.is_grantable FROM pg_attribute a
 JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace,
 LATERAL aclexplode(a.attacl) acl WHERE n.nspname='rss_audit'
 ) access WHERE grantee=0)
"#).fetch_one(c).await?;
    require(valid, Violation::Permissions)
}
