use std::fmt;

use bytes::Bytes;
use http_body::{Frame, SizeHint};

use crate::{RemoteMcpResponseBudgetError, RemoteMcpStreamError};

/// Explicit per-response delivery limits, carried by reserved admission.
///
/// These bound frames delivered by the guard, not allocation by a provider,
/// HTTP headers already returned, compressed wire bytes, or downstream queues.
/// No default production capacity is implied.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RemoteMcpDeliveryLimits {
    data_frame_bytes: usize,
    total_data_bytes: u64,
    total_trailer_bytes: usize,
    total_trailer_fields: usize,
    frames: u64,
}

impl fmt::Debug for RemoteMcpDeliveryLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteMcpDeliveryLimits(<redacted>)")
    }
}

impl RemoteMcpDeliveryLimits {
    /// Data/frame limits must be positive, and one data frame cannot exceed the
    /// total data allowance. Zero trailer limits reject nonempty trailers.
    ///
    /// Trailer bytes count every name/value pair, including duplicate values,
    /// across all trailer frames; frames count data, trailers, and empty frames.
    pub fn new(
        max_data_frame_bytes: usize,
        max_total_data_bytes: u64,
        max_total_trailer_bytes: usize,
        max_total_trailer_fields: usize,
        max_frames: u64,
    ) -> Result<Self, RemoteMcpResponseBudgetError> {
        let frame_bytes = u64::try_from(max_data_frame_bytes)
            .map_err(|_| RemoteMcpResponseBudgetError::InvalidLimits)?;
        if max_data_frame_bytes == 0
            || max_total_data_bytes == 0
            || frame_bytes > max_total_data_bytes
            || max_frames == 0
        {
            return Err(RemoteMcpResponseBudgetError::InvalidLimits);
        }
        Ok(Self {
            data_frame_bytes: max_data_frame_bytes,
            total_data_bytes: max_total_data_bytes,
            total_trailer_bytes: max_total_trailer_bytes,
            total_trailer_fields: max_total_trailer_fields,
            frames: max_frames,
        })
    }
}

pub(crate) struct DeliveryBudget {
    limits: RemoteMcpDeliveryLimits,
    data_bytes: u64,
    trailer_bytes: usize,
    trailer_fields: usize,
    frames: u64,
}

impl DeliveryBudget {
    pub(crate) const fn new(limits: RemoteMcpDeliveryLimits) -> Self {
        Self {
            limits,
            data_bytes: 0,
            trailer_bytes: 0,
            trailer_fields: 0,
            frames: 0,
        }
    }

    /// Updates counters only after the entire frame is admitted.
    pub(crate) fn admit(&mut self, frame: &Frame<Bytes>) -> Result<(), RemoteMcpStreamError> {
        let denied = RemoteMcpStreamError::DeliveryLimitExceeded;
        let frames = self.frames.checked_add(1).ok_or(denied)?;
        if frames > self.limits.frames {
            return Err(denied);
        }
        if let Some(data) = frame.data_ref() {
            if data.len() > self.limits.data_frame_bytes {
                return Err(denied);
            }
            let data_bytes = self
                .data_bytes
                .checked_add(u64::try_from(data.len()).map_err(|_| denied)?)
                .ok_or(denied)?;
            if data_bytes > self.limits.total_data_bytes {
                return Err(denied);
            }
            self.data_bytes = data_bytes;
        } else if let Some(trailers) = frame.trailers_ref() {
            let fields = self
                .trailer_fields
                .checked_add(trailers.len())
                .ok_or(denied)?;
            if fields > self.limits.total_trailer_fields {
                return Err(denied);
            }
            let mut bytes = self.trailer_bytes;
            for (name, value) in trailers {
                bytes = bytes
                    .checked_add(name.as_str().len())
                    .and_then(|bytes| bytes.checked_add(value.as_bytes().len()))
                    .ok_or(denied)?;
                if bytes > self.limits.total_trailer_bytes {
                    return Err(denied);
                }
            }
            self.trailer_fields = fields;
            self.trailer_bytes = bytes;
        } else {
            // Do not silently admit a future unsupported frame class.
            return Err(denied);
        }
        self.frames = frames;
        Ok(())
    }

    pub(crate) fn size_hint(&self, hint: &SizeHint) -> SizeHint {
        let remaining = self.limits.total_data_bytes.saturating_sub(self.data_bytes);
        let upper = hint.upper().unwrap_or(remaining).min(remaining);
        let mut bounded = SizeHint::new();
        bounded.set_lower(hint.lower().min(upper));
        bounded.set_upper(upper);
        bounded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn limits() -> RemoteMcpDeliveryLimits {
        RemoteMcpDeliveryLimits::new(4, 6, 6, 2, 4).unwrap()
    }

    #[test]
    fn limits_reject_zero_and_inconsistent_data_or_frame_budgets() {
        for (frame, total, frames) in [(0, 1, 1), (1, 0, 1), (2, 1, 1), (1, 1, 0)] {
            assert_eq!(
                RemoteMcpDeliveryLimits::new(frame, total, 0, 0, frames).unwrap_err(),
                RemoteMcpResponseBudgetError::InvalidLimits
            );
        }
        assert!(RemoteMcpDeliveryLimits::new(1, 1, 0, 0, 1).is_ok());
        assert_eq!(
            format!("{:?}", limits()),
            "RemoteMcpDeliveryLimits(<redacted>)"
        );
    }

    #[test]
    fn data_frames_have_independent_single_and_cumulative_limits() {
        let mut budget = DeliveryBudget::new(limits());
        assert_eq!(
            budget.admit(&Frame::data(Bytes::from_static(b"12345"))),
            Err(RemoteMcpStreamError::DeliveryLimitExceeded)
        );
        assert_eq!(budget.frames, 0);
        budget
            .admit(&Frame::data(Bytes::from_static(b"1234")))
            .unwrap();
        assert_eq!(
            budget.admit(&Frame::data(Bytes::from_static(b"123"))),
            Err(RemoteMcpStreamError::DeliveryLimitExceeded)
        );
        assert_eq!(budget.data_bytes, 4);
        budget
            .admit(&Frame::data(Bytes::from_static(b"12")))
            .unwrap();
        assert_eq!(budget.data_bytes, 6);
    }

    #[test]
    fn duplicate_trailer_values_count_fields_and_every_name_value_byte() {
        let mut trailers = HeaderMap::new();
        trailers.append("x", HeaderValue::from_static("a"));
        trailers.append("x", HeaderValue::from_static("b"));
        assert_eq!(trailers.len(), 2);
        let frame = Frame::trailers(trailers);
        let mut exact = DeliveryBudget::new(RemoteMcpDeliveryLimits::new(1, 1, 4, 2, 1).unwrap());
        exact.admit(&frame).unwrap();
        assert_eq!(exact.trailer_fields, 2);
        assert_eq!(exact.trailer_bytes, 4);
        for (bytes, fields) in [(3, 2), (4, 1), (0, 0)] {
            let mut denied =
                DeliveryBudget::new(RemoteMcpDeliveryLimits::new(1, 1, bytes, fields, 1).unwrap());
            assert_eq!(
                denied.admit(&frame),
                Err(RemoteMcpStreamError::DeliveryLimitExceeded)
            );
            assert_eq!(denied.trailer_bytes, 0);
            assert_eq!(denied.trailer_fields, 0);
            assert_eq!(denied.frames, 0);
        }
    }

    #[test]
    fn trailer_budgets_are_cumulative_across_frames() {
        let mut budget = DeliveryBudget::new(limits());
        let mut trailers = HeaderMap::new();
        trailers.insert("x", HeaderValue::from_static("ab"));
        let frame = Frame::trailers(trailers);
        budget.admit(&frame).unwrap();
        budget.admit(&frame).unwrap();
        assert_eq!(budget.trailer_bytes, 6);
        assert_eq!(
            budget.admit(&frame),
            Err(RemoteMcpStreamError::DeliveryLimitExceeded)
        );
        assert_eq!(budget.trailer_fields, 2);
    }

    #[test]
    fn empty_data_and_trailer_frames_cannot_evade_the_frame_limit() {
        let mut budget = DeliveryBudget::new(RemoteMcpDeliveryLimits::new(1, 1, 0, 0, 2).unwrap());
        budget.admit(&Frame::data(Bytes::new())).unwrap();
        budget.admit(&Frame::trailers(HeaderMap::new())).unwrap();
        assert_eq!(
            budget.admit(&Frame::data(Bytes::new())),
            Err(RemoteMcpStreamError::DeliveryLimitExceeded)
        );
    }

    #[test]
    fn counter_overflow_fails_closed_without_reset() {
        let mut budget = DeliveryBudget::new(
            RemoteMcpDeliveryLimits::new(1, u64::MAX, usize::MAX, usize::MAX, u64::MAX).unwrap(),
        );
        budget.data_bytes = u64::MAX;
        assert!(
            budget
                .admit(&Frame::data(Bytes::from_static(b"x")))
                .is_err()
        );
        budget.data_bytes = 0;
        budget.frames = u64::MAX;
        assert!(budget.admit(&Frame::data(Bytes::new())).is_err());
        budget.frames = 0;
        budget.trailer_bytes = usize::MAX;
        let mut trailers = HeaderMap::new();
        trailers.insert("x", HeaderValue::from_static("y"));
        assert!(budget.admit(&Frame::trailers(trailers.clone())).is_err());
        budget.trailer_bytes = 0;
        budget.trailer_fields = usize::MAX;
        assert!(budget.admit(&Frame::trailers(trailers)).is_err());
    }

    #[test]
    fn size_hints_do_not_advertise_more_than_remaining_data_capacity() {
        let mut budget = DeliveryBudget::new(limits());
        let hint = budget.size_hint(&SizeHint::with_exact(100));
        assert_eq!(hint.exact(), Some(6));
        budget
            .admit(&Frame::data(Bytes::from_static(b"1234")))
            .unwrap();
        assert_eq!(budget.size_hint(&SizeHint::new()).upper(), Some(2));
        assert_eq!(budget.size_hint(&SizeHint::with_exact(1)).exact(), Some(1));
        budget
            .admit(&Frame::data(Bytes::from_static(b"12")))
            .unwrap();
        assert_eq!(budget.size_hint(&SizeHint::new()).exact(), Some(0));
    }
}
