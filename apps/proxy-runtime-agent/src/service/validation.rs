use crate::proto;
use tonic::Status;

pub(crate) fn request(body: &proto::RuntimeReconcileRequest) -> Result<(), Status> {
    let invalid = || Status::invalid_argument("RUNTIME_REQUEST_INVALID");
    let t = body.target.as_ref().ok_or_else(invalid)?;
    if body.schema_version != 1
        || crate::check_runtime_target(t).is_err()
        || t.generation == 0
        || i64::try_from(t.generation).is_err()
        || t.fencing_token == 0
        || i64::try_from(t.fencing_token).is_err()
        || !apex_domain::is_lowercase_uuidv7(&body.operation_id)
        || !apex_domain::is_lowercase_uuidv7(&body.command_id)
        || !crate::shapes::hex_hash(&body.config_hash)
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn states(snapshot: &proto::RuntimeAuthoritySnapshot) -> Result<(), Status> {
    use proto::{ProxyDesiredState as D, ProxyObservedState as O};
    if !matches!(
        D::try_from(snapshot.desired_state),
        Ok(D::Serving | D::Paused | D::Retired)
    ) || !matches!(
        O::try_from(snapshot.observed_state),
        Ok(O::Pending | O::Reconciling | O::Failed | O::NotServing)
    ) {
        return Err(Status::failed_precondition("RUNTIME_OPERATION_NOT_CURRENT"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_wire_never_reaches_authority() {
        let valid = proto::RuntimeReconcileRequest {
            schema_version: 1,
            target: Some(proto::RuntimeTarget {
                workspace_id: "work".into(),
                namespace_id: "ns".into(),
                proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
                revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
                generation: 1,
                fencing_token: 9_007_199_254_740_993,
            }),
            operation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05".into(),
            command_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06".into(),
            config_hash: "a".repeat(64),
        };
        assert!(request(&valid).is_ok());
        let mutations: &[fn(&mut proto::RuntimeReconcileRequest)] = &[
            |r| r.schema_version = 0,
            |r| r.schema_version = 2,
            |r| r.target = None,
            |r| r.operation_id.clear(),
            |r| r.command_id.clear(),
            |r| r.operation_id = r.operation_id.to_uppercase(),
            |r| r.command_id.replace_range(14..15, "4"),
            |r| r.config_hash = "A".repeat(64),
            |r| r.config_hash = "g".repeat(64),
            |r| r.config_hash = "a".repeat(63),
            |r| r.target.as_mut().unwrap().generation = 0,
            |r| r.target.as_mut().unwrap().fencing_token = u64::MAX,
            |r| r.target.as_mut().unwrap().workspace_id = "..".into(),
        ];
        for mutate in mutations {
            let mut body = valid.clone();
            mutate(&mut body);
            assert!(
                request(&body).is_err(),
                "malformed correlation admitted: {body:?}"
            );
        }
        use prost::Message;
        assert_eq!(
            proto::RuntimeReconcileRequest::decode(valid.encode_to_vec().as_slice()).unwrap(),
            valid
        );
        let json = serde_json::to_string(&valid).unwrap();
        assert!(json.contains("\"9007199254740993\""));
        assert_eq!(
            serde_json::from_str::<proto::RuntimeReconcileRequest>(&json).unwrap(),
            valid
        );
    }
    #[test]
    fn terminal_default_unknown_observation_and_desire_refuse() {
        for observed in [0, 3, 4, 5, 8, 9, 999] {
            assert!(
                states(&proto::RuntimeAuthoritySnapshot {
                    desired_state: 1,
                    observed_state: observed,
                    ..Default::default()
                })
                .is_err()
            );
        }
        for desired in [0, 999] {
            assert!(
                states(&proto::RuntimeAuthoritySnapshot {
                    desired_state: desired,
                    observed_state: 1,
                    ..Default::default()
                })
                .is_err()
            );
        }
    }
    #[test]
    fn retryable_failed_and_not_serving_remain_nonterminal() {
        for observed in [6, 7] {
            assert!(
                states(&proto::RuntimeAuthoritySnapshot {
                    desired_state: 1,
                    observed_state: observed,
                    ..Default::default()
                })
                .is_ok(),
                "retryable state {observed} must remain eligible for current authority"
            );
        }
    }
}
