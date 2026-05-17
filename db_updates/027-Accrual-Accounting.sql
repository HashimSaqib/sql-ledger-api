-- Accrual Accounting
-- Lets users mark an AP/AR transaction or AR invoice as an accrual that amortises
-- over N months/quarters/years. The accrual postings live on a separate linked GL
-- entry (gl.accrual_source = '<module>:<trans_id>') so the source AR/AP's acc_trans
-- rows stay pristine (the rebuild path joins by trans_id and would otherwise need to
-- filter accrual rows everywhere).
--
-- Schema:
--   ar.accrual / ap.accrual JSONB    {period: 'monthly'|'quarterly'|'yearly',
--                                     length: int, startdate: 'YYYY-MM-DD',
--                                     accrual_id: int}  -- nullable, NULL = no accrual
--   gl.accrual_source TEXT           '<module>:<source_id>'  -- back-pointer, blocks direct edits
--   defaults.accrual_ap_chart_id     chart.id of the AP accrual account (e.g. 1300)
--   defaults.accrual_ar_chart_id     chart.id of the AR accrual account (e.g. 2305)

ALTER TABLE ar ADD COLUMN IF NOT EXISTS accrual JSONB;
ALTER TABLE ap ADD COLUMN IF NOT EXISTS accrual JSONB;
ALTER TABLE gl ADD COLUMN IF NOT EXISTS accrual_source TEXT;

CREATE INDEX IF NOT EXISTS gl_accrual_source_idx ON gl (accrual_source);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM defaults WHERE fldname = 'accrual_ap_chart_id'
  ) THEN
    INSERT INTO defaults (fldname, fldvalue) VALUES ('accrual_ap_chart_id', '');
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM defaults WHERE fldname = 'accrual_ar_chart_id'
  ) THEN
    INSERT INTO defaults (fldname, fldvalue) VALUES ('accrual_ar_chart_id', '');
  END IF;
END $$;

INSERT INTO db_updates (version, last_update) VALUES ('027', 'Accrual Accounting');
