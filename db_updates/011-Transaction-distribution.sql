
CREATE TABLE transaction_distribution (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(255) NOT NULL,
    trans_id INTEGER NOT NULL,
    amount double precision NOT NULL,
    based_on VARCHAR(50),
    module VARCHAR(50) NOT NULL
);