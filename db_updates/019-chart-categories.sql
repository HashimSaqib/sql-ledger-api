CREATE TABLE IF NOT EXISTS chart_categories (
    id          SERIAL PRIMARY KEY,
    accno       text NOT NULL,
    description text NOT NULL
);

CREATE TABLE IF NOT EXISTS chart_category_links (
    id          SERIAL PRIMARY KEY,
    chart_id    int  NOT NULL,
    category_id int  NOT NULL REFERENCES chart_categories(id) ON DELETE CASCADE,
    UNIQUE(chart_id, category_id)
);

CREATE INDEX IF NOT EXISTS idx_chart_category_links_chart_id    ON chart_category_links(chart_id);
CREATE INDEX IF NOT EXISTS idx_chart_category_links_category_id ON chart_category_links(category_id);
