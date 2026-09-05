use apex_control_plane_api::proto::ProxyDesiredState;
use apex_control_plane_api::{
    ExactScope, PostgresProxyStore, ProxyId, ProxyRevisionId, SubmitProxyOperation,
};
use apex_durability::{canonical_event_hash, proto as evidence};
use postgres::{Client, NoTls};
use prost_types::{Struct, Value, value::Kind};

pub struct Database {
    pub url: String,
    base_url: String,
    schema: String,
}
impl Database {
    pub fn new() -> Self {
        let base_url = std::env::var("APEX_PROXY_JOURNAL_TEST_DATABASE_URL")
            .expect("required disposable PostgreSQL: APEX_PROXY_JOURNAL_TEST_DATABASE_URL");
        let config: postgres::Config = base_url.parse().unwrap();
        assert!(!config.get_hosts().is_empty());
        assert!(
            config.get_hosts().iter().all(|host| match host {
                postgres::config::Host::Tcp(host) => host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()),
                #[cfg(unix)]
                postgres::config::Host::Unix(_) => false,
            }),
            "recovery test database must be loopback-only"
        );
        let schema = format!("working_proxy_recovery_{}", uuid::Uuid::now_v7().simple());
        let mut client =
            Client::connect(&base_url, NoTls).expect("dedicated PostgreSQL unavailable");
        client
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let database = Self {
            url,
            base_url,
            schema,
        };
        let _store = PostgresProxyStore::connect(&database.url).unwrap();
        let input = submission();
        database.seed(&input);
        database
    }
    pub fn seed(&self, input: &SubmitProxyOperation) {
        let mut client = self.client();
        client.execute("INSERT INTO mcp_proxies (proxy_id,workspace_id,namespace_id,display_name,
            slug,lifecycle_state,redaction_status,active_revision_id,created_at_micros,desired_state)
            VALUES ($1,$3,$4,'Recovery test',$5,'draft','redacted',$2,0,'draft')",
            &[input.proxy_id.as_uuid(), input.revision_id.as_uuid(), &input.scope.workspace_id,
              &input.scope.namespace_id, &input.proxy_id.to_string()]).unwrap();
        client.execute("INSERT INTO mcp_proxy_revisions (proxy_id,revision_id,spec_json,config_hash,
            lifecycle_state,redaction_status,created_by,created_at_micros,created_at,is_published)
            VALUES ($1,$2,'{}',$3,'draft','redacted','operator',0,'2024-05-03T12:34:56.123456Z',TRUE)",
            &[input.proxy_id.as_uuid(), input.revision_id.as_uuid(), &"0".repeat(64)]).unwrap();
    }
    pub fn client(&self) -> Client {
        Client::connect(&self.url, NoTls).unwrap()
    }
}

pub fn another_submission() -> SubmitProxyOperation {
    let mut input = submission();
    input.proxy_id = ProxyId::new(uuid::Uuid::now_v7().to_string()).unwrap();
    input.revision_id = ProxyRevisionId::new(uuid::Uuid::now_v7().to_string()).unwrap();
    input.expected_revision_id = Some(input.revision_id.clone());
    input.request_id = uuid::Uuid::now_v7().to_string();
    input.evidence.run_id = input.request_id.clone();
    input.evidence.trace_id = input.request_id.clone();
    input.evidence.data.as_mut().unwrap().fields.insert(
        "proxy_id".into(),
        Value {
            kind: Some(Kind::StringValue(input.proxy_id.to_string())),
        },
    );
    input.evidence.integrity.as_mut().unwrap().event_hash =
        canonical_event_hash(&input.evidence).unwrap();
    input
}
impl Drop for Database {
    fn drop(&mut self) {
        // Exact generated target only; never drop a database or caller-supplied schema.
        if self.schema.starts_with("working_proxy_recovery_")
            && self
                .schema
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            && let Ok(mut client) = Client::connect(&self.base_url, NoTls)
        {
            let _ = client.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema));
        }
    }
}

pub fn submission() -> SubmitProxyOperation {
    let request = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e87";
    let proxy = ProxyId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84").unwrap();
    let revision = ProxyRevisionId::new("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85").unwrap();
    let scope = ExactScope {
        workspace_id: "workspace".into(),
        namespace_id: "namespace".into(),
    };
    let mut event = evidence::EventEnvelope {
        event_id: uuid::Uuid::now_v7().to_string(),
        timestamp: "2024-05-03T12:34:56.123456Z".into(),
        r#type: 7,
        agent_id: "apex-control-gateway".into(),
        run_id: request.into(),
        parent_run_id: None,
        trace_id: request.into(),
        scope: Some(evidence::Scope {
            workspace_id: scope.workspace_id.clone(),
            namespace_id: scope.namespace_id.clone(),
            agent_group_ids: vec![],
        }),
        actor: Some(evidence::Actor {
            r#type: 3,
            id: "apex-control-plane".into(),
        }),
        version: Some(evidence::Version {
            agent_code: "apex-control-gateway".into(),
            prompt: "proxy-lifecycle-v1".into(),
            model: "n-a".into(),
        }),
        data: Some(Struct {
            fields: [(
                "proxy_id".into(),
                Value {
                    kind: Some(Kind::StringValue(proxy.to_string())),
                },
            )]
            .into_iter()
            .collect(),
        }),
        integrity: Some(evidence::Integrity {
            prev_hash: None,
            event_hash: String::new(),
        }),
        schema_version: 1,
    };
    event.integrity.as_mut().unwrap().event_hash = canonical_event_hash(&event).unwrap();
    SubmitProxyOperation {
        scope,
        proxy_id: proxy,
        request_id: request.into(),
        expected_revision_id: Some(revision.clone()),
        revision_id: revision,
        expected_generation: 0,
        desired_state: ProxyDesiredState::Serving,
        evidence: event,
    }
}
