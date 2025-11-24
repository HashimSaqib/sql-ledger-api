CREATE TABLE onboarding (
    id SERIAL PRIMARY KEY,
    fldname VARCHAR(255) NOT NULL,
    fldvalue BOOLEAN
);

INSERT INTO onboarding (fldname, fldvalue) VALUES ('coa', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('departments', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('projects', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('bank_accounts', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('defaults', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('services', false);
INSERT INTO onboarding (fldname, fldvalue) VALUES ('stations', false);






