-- Optional JSON from payment providers (e.g. Revolut merchant + card on card payments).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'bank_transactions'
      AND column_name = 'provider_metadata'
  ) THEN
    ALTER TABLE bank_transactions ADD COLUMN provider_metadata JSONB;
  END IF;
END $$;
