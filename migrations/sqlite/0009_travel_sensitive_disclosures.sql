ALTER TABLE travel_disclosure_receipts
ADD COLUMN source_references_included INTEGER NOT NULL DEFAULT 0
CHECK (source_references_included IN (0, 1));
