-- Widen bank_transaction_code so provider-specific types (e.g. Revolut) are not truncated.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'bank_transactions'
      AND column_name = 'bank_transaction_code'
      AND (
        character_maximum_length IS NOT NULL
        AND character_maximum_length < 128
      )
  ) THEN
    ALTER TABLE bank_transactions
      ALTER COLUMN bank_transaction_code TYPE VARCHAR(128);
  END IF;
END $$;
