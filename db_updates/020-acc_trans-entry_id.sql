-- Stable unique row identifier for acc_trans (legacy "id" is not unique without trans_id).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'acc_trans'
      AND column_name = 'entry_id'
  ) THEN
    CREATE SEQUENCE acc_trans_entry_id_seq;
    ALTER TABLE acc_trans ADD COLUMN entry_id bigint;
    UPDATE acc_trans SET entry_id = nextval('acc_trans_entry_id_seq')
      WHERE entry_id IS NULL;
    ALTER TABLE acc_trans ALTER COLUMN entry_id SET DEFAULT nextval('acc_trans_entry_id_seq');
    ALTER SEQUENCE acc_trans_entry_id_seq OWNED BY acc_trans.entry_id;
    ALTER TABLE acc_trans ALTER COLUMN entry_id SET NOT NULL;
    CREATE UNIQUE INDEX acc_trans_entry_id_key ON acc_trans (entry_id);
  END IF;
END $$;
