ALTER TABLE travel_disclosure_receipts
ADD COLUMN sensitive_profile_included INTEGER NOT NULL DEFAULT 0
CHECK (sensitive_profile_included IN (0, 1));
