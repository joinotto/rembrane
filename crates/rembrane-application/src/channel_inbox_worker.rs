use rembrane_domain::WorkspaceId;

use crate::{
    ApplicationError, ChannelInboxRepository, ChannelMessageProcessor, MAX_CHANNEL_INBOX_PAGE,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChannelDispatchReport {
    pub attempted: usize,
    pub completed: usize,
    pub failed: usize,
}

pub struct ChannelInboxWorker<'worker, Repository, Processor> {
    repository: &'worker mut Repository,
    processor: &'worker mut Processor,
}

impl<'worker, Repository, Processor> ChannelInboxWorker<'worker, Repository, Processor>
where
    Repository: ChannelInboxRepository,
    Processor: ChannelMessageProcessor,
{
    pub fn new(repository: &'worker mut Repository, processor: &'worker mut Processor) -> Self {
        Self {
            repository,
            processor,
        }
    }

    pub fn process_batch(
        &mut self,
        workspace_id: &WorkspaceId,
        limit: usize,
    ) -> Result<ChannelDispatchReport, ApplicationError> {
        if !(1..=MAX_CHANNEL_INBOX_PAGE).contains(&limit) {
            return Err(ApplicationError::Validation(
                "channel dispatch batch limit is invalid".to_owned(),
            ));
        }
        let pending = self
            .repository
            .pending_channel_messages(workspace_id, limit)?;
        let mut report = ChannelDispatchReport::default();
        for message in pending {
            report.attempted += 1;
            if self.processor.process_channel_message(&message).is_err() {
                report.failed += 1;
                continue;
            }
            self.repository.complete_channel_message(
                message.workspace_id(),
                message.channel(),
                message.event_id(),
            )?;
            report.completed += 1;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

    use super::ChannelInboxWorker;
    use crate::{
        ApplicationError, ChannelInboxRepository, ChannelMessageProcessor, MAX_CHANNEL_INBOX_PAGE,
    };

    struct Inbox {
        pending: Vec<VerifiedChannelMessage>,
        completed: Vec<String>,
    }

    impl ChannelInboxRepository for Inbox {
        fn pending_channel_messages(
            &self,
            workspace_id: &WorkspaceId,
            limit: usize,
        ) -> Result<Vec<VerifiedChannelMessage>, ApplicationError> {
            Ok(self
                .pending
                .iter()
                .filter(|message| message.workspace_id() == workspace_id)
                .take(limit)
                .cloned()
                .collect())
        }

        fn complete_channel_message(
            &mut self,
            workspace_id: &WorkspaceId,
            _channel: ChannelKind,
            event_id: &str,
        ) -> Result<(), ApplicationError> {
            if workspace_id.as_str() != "workspace_01" {
                return Err(ApplicationError::AccessDenied);
            }
            self.completed.push(event_id.to_owned());
            Ok(())
        }
    }

    struct Processor {
        seen: Vec<String>,
        fail_event: &'static str,
    }

    impl ChannelMessageProcessor for Processor {
        fn process_channel_message(
            &mut self,
            message: &VerifiedChannelMessage,
        ) -> Result<(), ApplicationError> {
            self.seen.push(message.event_id().to_owned());
            if message.event_id() == self.fail_event {
                return Err(ApplicationError::StorageUnavailable);
            }
            Ok(())
        }
    }

    fn message(event_id: &str) -> VerifiedChannelMessage {
        VerifiedChannelMessage::from_authenticated_transport(
            ChannelKind::WhatsAppBusiness,
            event_id,
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ClientId::new("client_01"),
            "continue",
            1_000,
        )
        .expect("fixture should validate")
    }

    #[test]
    fn completes_only_successful_messages_and_leaves_failures_retryable() {
        let mut inbox = Inbox {
            pending: vec![message("event_01"), message("event_02")],
            completed: Vec::new(),
        };
        let mut processor = Processor {
            seen: Vec::new(),
            fail_event: "event_02",
        };
        let report = ChannelInboxWorker::new(&mut inbox, &mut processor)
            .process_batch(&WorkspaceId::new("workspace_01"), 10)
            .expect("batch should continue across handler failure");
        assert_eq!(report.attempted, 2);
        assert_eq!(report.completed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(inbox.completed, vec!["event_01"]);
        assert_eq!(processor.seen, vec!["event_01", "event_02"]);
    }

    #[test]
    fn rejects_unbounded_batches_before_reading_the_inbox() {
        let mut inbox = Inbox {
            pending: Vec::new(),
            completed: Vec::new(),
        };
        let mut processor = Processor {
            seen: Vec::new(),
            fail_event: "",
        };
        assert!(matches!(
            ChannelInboxWorker::new(&mut inbox, &mut processor).process_batch(
                &WorkspaceId::new("workspace_01"),
                MAX_CHANNEL_INBOX_PAGE + 1
            ),
            Err(ApplicationError::Validation(_))
        ));
    }
}
