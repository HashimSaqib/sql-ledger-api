-- Maps the Swiss SME Chart of Accounts (Mattle, Helbling, Pfaff, 2nd edition) to SQL-Ledger
-- Reflects the chart of accounts for a corporation (Aktiengesellschaft) using the effective method (Effektive MWST-Methode).
-- The script deletes the existing chart of accounts (if present).
-- Use this script only for new installations or databases without existing entries.


DELETE FROM chart;

-----------------
--- 1 AKTIVEN ---
-----------------

INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1', 'AKTIVEN', 'H', 'A', '', '1', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('10', 'UMLAUFVERMÖGEN', 'H', 'A', '', '100', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('100', 'FLÜSSIGE MITTEL', 'H', 'A', '', '100', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1000', 'Kasse', 'A', 'A', 'AR_paid:AP_paid', '100', false, true, 'kassa');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1020', 'Bank', 'A', 'A', 'AR_paid:AP_paid', '100', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('106', 'KURZFRISTIG GEHALTENE AKTIVEN MIT BÖRSENKURS', 'H', 'A', '', '106', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1060', 'Wertschriften mit Börsenkurs', 'A', 'A', 'AP_amount', '106', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('109', 'TRANSFERKONTO', 'H', 'A', '', '109', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1090', 'Transferkonto', 'A', 'A', 'AR_paid:AP_paid', '109', false, true, 'transfer');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1099', 'Unklare Beträge', 'A', 'A', 'AP_amount', '109', false, true, 'abklärung');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('110', 'FORDERUNGEN AUS LIEFERUNGEN UND LEISTUNGEN GEGENÜBER DRITTEN', 'H', 'A', '', '110', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1100', 'Forderungen Schweiz', 'A', 'A', 'AR', '110', false, false, 'forderungenschweiz');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1101', 'Forderungen Ausland', 'A', 'A', 'AR', '110', false, false, 'forderungenauslandchf');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1102', 'Forderungen Ausland Fremdwährungen', 'A', 'A', 'AR', '110', false, false, 'forderungenauslandandere');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1103', 'Forderungen aus Lieferungen und Leistungen FiBu', 'A', 'A', 'AR_paid', '110', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1109', 'Wertberichtigungen Forderungen aus Lieferungen und Leistungen gegenüber Dritten', 'A', 'A', '', '110', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('111', 'FORDERUNGEN AUS LIEFERUNGEN UND LEISTUNGEN GEGENÜBER BETEILIGUNGEN', 'H', 'A', '', '111', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1110', 'Forderungen aus Lieferungen und Leistungen gegenüber Beteiligungen', 'A', 'A', '', '111', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('112', 'FORDERUNGEN AUS LIEFERUNGEN UND LEISTUNGEN GEGENÜBER BETEILIGTEN UND ORGANEN', 'H', 'A', '', '112', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1120', 'Forderungen aus Lieferungen und Leistungen gegenüber Beteiligten', 'A', 'A', '', '112', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('114', 'ÜBRIGE KURZFRISTIGE FORDERUNGEN GEGENÜBER DRITTEN', 'H', 'A', '', '114', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('115', 'ÜBRIGE KURZFRISTIGE FORDERUNGEN GEGENÜBER BETEILIGUNGEN', 'H', 'A', '', '115', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('116', 'ÜBRIGE KURZFRISTIGE FORDERUNGEN GEGENÜBER BETEILIGTEN UND ORGANEN', 'H', 'A', '', '116', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('117', 'ÜBRIGE KURZFRISTIGE FORDERUNGEN GEGENÜBER STAATLICHEN STELLEN', 'H', 'A', '', '117', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('11700', 'Vorsteuer 8.1% auf Mat. + DL', 'A', 'A', 'AP_tax', '117', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('11710', 'Zoll auf Mat. + DL', 'A', 'A', 'AP_tax', '117', false, true, 'zollkonto1');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('11711', 'Zoll auf Inv. + übr. BA', 'A', 'A', 'AP_tax', '117', false, true, 'zollkonto2');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('11720', 'Vorsteuer 2.6% auf Mat. + DL', 'A', 'A', 'AP_tax', '117', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('11730', 'Vorsteuer 8.1% auf Inv. + übr. BA', 'A', 'A', 'AP_tax', '117', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('11740', 'Vorsteuer 3.8% auf Inv. + übr. BA', 'A', 'A', 'AP_tax', '117', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('11750', 'Vorsteuer 2.6% auf Inv. + übr. BA', 'A', 'A', 'AP_tax', '117', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('11760', 'Vorsteuer 8.1% Bezugsteuer', 'A', 'A', 'AP_tax', '117', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1177', 'Forderungen gegenüber Oberzolldirektion', 'A', 'A', '', '117', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1179', 'Verrechnungssteuer', 'A', 'A', '', '117', false, true, 'verrechnungssteuer');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('118', 'ÜBRIGE KURZFRISTIGE FORDERUNGEN GEGENÜBER SOZIALVERSICHERUNGEN', 'H', 'A', '', '118', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('119', 'ANZAHLUNGEN', 'H', 'A', '', '119', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1192', 'Geleistete Anzahlungen', 'A', 'A', 'AP_paid', '119', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('120', 'VORRÄTE UND NICHT FAKTURIERTE DIENSTLEISTUNGEN', 'H', 'A', '', '120', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1280', 'Nicht fakturierte Dienstleistungen', 'A', 'A', 'IC', '120', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('130', 'AKTIVE RECHNUNGSABGRENZUNGEN', 'H', 'A', '', '130', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1300', 'Im Voraus bezahlter Aufwand', 'A', 'A', '', '130', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1301', 'Noch nicht erhaltener Ertrag', 'A', 'A', '', '130', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1302', 'Arbeitgeberbeitragsreserve', 'A', 'A', '', '130', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1310', 'Aktive Rechnungsabgrenzung', 'A', 'A', '', '130', false, true, 'aktiverechnungsabgrenzung');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('14', 'ANLAGEVERMÖGEN', 'H', 'A', '', '140', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('140', 'FINANZANLAGEN', 'H', 'A', '', '140', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1400', 'Wertschriften des Anlagevermögens', 'A', 'A', '', '140', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('144', 'LANGFRISTIGE FORDERUNGEN GEGENÜBER DRITTEN', 'H', 'A', '', '144', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1440', 'Darlehensforderungen gegenüber Dritten', 'A', 'A', '', '144', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('145', 'LANGFRISTIGE FORDERUNGEN GEGENÜBER BETEILIGUNGEN', 'H', 'A', '', '145', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1450', 'Darlehensforderungen gegenüber Beteiligungen', 'A', 'A', '', '145', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('146', 'LANGFRISTIGE FORDERUNGEN GEGENÜBER BETEILIGTEN UND ORGANEN', 'H', 'A', '', '146', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1460', 'Darlehensforderungen gegenüber Beteiligten', 'A', 'A', '', '146', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('148', 'BETEILIGUNGEN', 'H', 'A', '', '148', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1480', 'Beteiligungen', 'A', 'A', '', '148', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('150', 'MOBILE SACHANLAGEN', 'H', 'A', '', '150', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1500', 'Maschinen und Apparate', 'A', 'A', 'AP_amount', '150', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1510', 'Mobiliar und Einrichtungen', 'A', 'A', 'AP_amount', '150', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1520', 'Büromaschinen', 'A', 'A', 'AR_amount:AP_amount', '150', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1530', 'Fahrzeuge', 'A', 'A', 'AP_amount', '150', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1540', 'Werkzeuge und Geräte', 'A', 'A', 'AP_amount', '150', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1590', 'Übrige mobile Sachanlagen', 'A', 'A', 'AP_amount', '150', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('160', 'IMMOBILE SACHANLAGEN', 'H', 'A', '', '160', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1600', 'Immobile Sachanlagen', 'A', 'A', '', '160', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('170', 'IMMATERIELLE WERTE', 'H', 'A', '', '170', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1700', 'Patente, Marken, Lizenzen, Urheberrechte', 'A', 'A', 'AP_amount', '170', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1740', 'Selber entwickelte Software', 'A', 'A', '', '170', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1741', 'Erworbene Software', 'A', 'A', 'AP_amount', '170', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1790', 'Übrige immaterielle Werte', 'A', 'A', '', '170', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('180', 'NICHT EINBEZAHLTES GRUNDKAPITAL', 'H', 'A', '', '180', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('1800', 'Nicht einbezahltes Grundkapital', 'A', 'A', '', '180', false, true, '');

------------------
--- 2 PASSIVEN ---
------------------

INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2', 'PASSIVEN', 'H', 'L', '', '2', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('20', 'KURZFRISTIGES FREMDKAPITAL', 'H', 'L', '', '200', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('200', 'VERBINDLICHKEITEN AUS LIEFERUNGEN UND LEISTUNGEN GEGENÜBER DRITTEN', 'H', 'L', '', '200', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2000', 'Verbindlichkeiten aus Lieferungen und Leistungen', 'A', 'L', 'AP', '200', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2001', 'Verbindlichkeiten aus Lieferungen und Leistungen FiBu', 'A', 'L', '', '200', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2002', 'Verbindlichkeiten für Personalaufwand', 'A', 'L', '', '200', false, true, 'lohnzahlung');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('201', 'VERBINDLICHKEITEN AUS LIEFERUNGEN UND LEISTUNGEN GEGENÜBER BETEILIGTEN UND ORGANEN', 'H', 'Q', '', '201', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2010', 'Verbindlichkeiten aus Lieferungen und Leistungen gegenüber Beteiligten und Organen', 'A', 'L', 'AP', '201', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('202', 'VERBINDLICHKEITEN AUS LIEFERUNGEN UND LEISTUNGEN GEGENÜBER BETEILIGUNGEN', 'H', 'Q', '', '202', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2020', 'Verbindlichkeiten aus Lieferungen und Leistungen gegenüber Beteiligungen', 'A', 'L', 'AP', '202', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('203', 'ERHALTENE ANZAHLUNGEN VON DRITTEN', 'H', 'L', '', '203', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2030', 'Erhaltene Anzahlungen von Dritten', 'A', 'L', 'AR_amount:IC_income', '203', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('214', 'KURZFRISTIGE VERZINSLICHE VERBINDLICHKEITEN GEGENÜBER DRITTEN', 'H', 'L', '', '214', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('215', 'KURZFRISTIGE VERZINSLICHE VERBINDLICHKEITEN GEGENÜBER BETEILIGUNGEN', 'H', 'L', '', '215', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('216', 'KURZFRISTIGE VERZINSLICHE VERBINDLICHKEITEN GEGENÜBER BETEILIGTEN UND ORGANEN', 'H', 'L', '', '216', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2160', 'Kontokorrent Gesellschafter', 'A', 'L', 'AR_paid:AP_paid', '216', false, true, 'kontokorrent');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('220', 'KURZFRISTIGE VERZINSLICHE VERBINDLICHKEITEN GEGENÜBER STAATLICHEN STELLEN', 'H', 'L', '', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2200', 'Geschuldete MWST', 'A', 'L', 'AP_amount', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22010', 'MWST 8.1%', 'A', 'L', 'AR_tax:IC_taxpart:IC_taxservice', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22020', 'MWST 3.8%', 'A', 'L', 'AR_tax:IC_taxpart:IC_taxservice', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22030', 'MWST 2.6%', 'A', 'L', 'AR_tax:IC_taxpart:IC_taxservice', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22040', 'Bezugsteuer 8.1%', 'A', 'L', 'AP_tax', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22050', 'Befreite Leistungen, Exporte MWST 0% (Ziff. 220)', 'A', 'L', '', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22051', 'Leistungen im Ausland MWST 0% (Ziff. 221)', 'A', 'L', '', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22052', 'Nicht steuerbare Leistungen MWST 0% (Ziff. 230)', 'A', 'L', '', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22053', 'Subventionen MWST 0% (Ziff. 900)', 'A', 'L', '', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22054', 'Spenden, Dividenden, Schadenersatz MWST 0% (Ziff. 910)', 'A', 'L', '', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22055', 'Nichtentgelt MWST 0%', 'A', 'L', '', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('22060', 'Verrechnungssteuer', 'A', 'L', 'AP_amount', '220', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('221', 'ÜBRIGE KURZFRISTIGE VERBINDLICHKEITEN GEGENÜBER DRITTEN (UNVERZINSLICH)', 'H', 'L', '', '221', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2215', 'Kreditkarte', 'A', 'L', '', '221', false, true, 'kreditkarten');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('225', 'ÜBRIGE KURZFRISTIGE VERBINDLICHKEITEN GEGENÜBER BETEILIGUNGEN (UNVERZINSLICH)', 'H', 'L', '', '225', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('226', 'ÜBRIGE KURZFRISTIGE VERBINDLICHKEITEN GEGENÜBER BETEILIGTEN UND ORGANEN (UNVERZINSLICH)', 'H', 'L', '', '226', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2261', 'Beschlossene Ausschüttungen', 'A', 'L', '', '226', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('227', 'ÜBRIGE KURZFRISTIGE VERBINDLICHKEITEN GEGENÜBER SOZIALVERSICHERUNGEN UND VORSORGEEINRICHTUNGEN (UNVERZINSLICH)', 'H', 'L', '', '227', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2270', 'Kontokorrent Vorsorgeeinrichtung', 'A', 'L', 'AP_amount', '227', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2271', 'Kontokorrent AHV, IV, EO, ALV', 'A', 'L', 'AP_amount', '227', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2272', 'Kontokorrent FAK', 'A', 'L', 'AP_amount', '227', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2273', 'Kontokorrent Unfallversicherung', 'A', 'L', 'AP_amount', '227', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2274', 'Kontokorrent Krankentaggeldversicherung', 'A', 'L', 'AP_amount', '227', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2279', 'Kontokorrent Quellensteuer', 'A', 'L', 'AP_amount', '227', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('230', 'PASSIVE RECHNUNGSABGRENZUNG UND KURZFRISTIGE RÜCKSTELLUNGEN', 'H', 'L', '', '230', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2300', 'Noch nicht bezahlter Aufwand', 'A', 'L', '', '230', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2301', 'Im Voraus erhaltener Ertrag', 'A', 'L', '', '230', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2310', 'Passive Rechnungsabgrenzung', 'A', 'L', '', '230', false, true, 'passiverechnungsabgrenzung');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2330', 'Kurzfristige Rückstellungen', 'A', 'L', '', '230', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2340', 'Steuerrückstellungen', 'A', 'L', 'AP_amount', '230', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('24', 'LANGFRISTIGES FREMDKAPITAL', 'H', 'L', '', '240', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('240', 'LANGFRISTIGE VERZINSLICHE VERBINDLICHKEITEN', 'H', 'L', '', '240', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2400', 'Bankverbindlichkeiten langfristig', 'A', 'L', '', '240', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('245', 'LANGFRISTIGE VERZINSLICHE VERBINDLICHKEITEN GEGENÜBER DRITTEN', 'H', 'L', '', '245', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('247', 'LANGFRISTIGE VERZINSLICHE VERBINDLICHKEITEN GEGENÜBER BETEILIGUNGEN', 'H', 'L', '', '247', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('248', 'LANGFRISTIGE VERZINSLICHE VERBINDLICHKEITEN GEGENÜBER BETEILIGTEN UND ORGANEN', 'H', 'L', '', '248', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('250', 'ÜBRIGE LANGFRISTIGE VERBINDLICHKEITEN GEGENÜBER DRITTEN (UNVERZINSLICH)', 'H', 'L', '', '250', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('255', 'ÜBRIGE LANGFRISTIGE VERBINDLICHKEITEN GEGENÜBER BETEILIGUNGEN (UNVERZINSLICH)', 'H', 'L', '', '255', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('256', 'ÜBRIGE LANGFRISITGE VERBINDLICHKEITEN GEGENÜBER BETEILIGTEN UND ORGANEN (UNVERZINSLICH)', 'H', 'L', '', '256', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('260', 'RÜCKSTELLUNGEN SOWIE VOM GESETZ VORGESEHENE ÄHNLICHE POSITIONEN', 'H', 'L', '', '260', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2600', 'Rückstellungen', 'A', 'L', '', '260', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('28', 'EIGENKAPITAL', 'H', 'Q', '', '280', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('280', 'GRUNDKAPITAL', 'H', 'Q', '', '280', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2800', 'Grundkapital', 'A', 'Q', '', '280', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2950', 'Allgemeine gesetzliche Gewinnreserve', 'A', 'Q', '', '295', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2952', 'Reserve für eigene Aktien', 'A', 'Q', '', '295', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('290', 'GESETZLICHE KAPITALRESERVE', 'H', 'Q', '', '290', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2900', 'Aufgeld (Agio) bei Gründung oder Kapitalerhöhung', 'A', 'Q', '', '290', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2901', 'Übrige Einlagen, Aufgelder und Zuschüsse', 'A', 'Q', '', '290', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('295', 'GESETZLICHE GEWINNRESERVE', 'H', 'Q', '', '295', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2951', 'Aufwertungsreserve', 'A', 'Q', '', '295', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('296', 'FREIWILLIGE GEWINNRESERVEN', 'H', 'Q', '', '296', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2960', 'Andere Reserven', 'A', 'Q', '', '296', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2961', 'Statutarische und beschlussmässige Gewinnreserven', 'A', 'Q', '', '296', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('297', 'BILANZGEWINN ODER BILANZVERLUST', 'H', 'Q', '', '297', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2970', 'Gewinnvortrag oder Verlustvortrag', 'A', 'Q', '', '297', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2979', 'Jahresgewinn oder Jahresverlust', 'A', 'Q', '', '297', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('298', 'EIGENE KAPITALANTEILE', 'H', 'Q', '', '298', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('2980', 'Eigene Aktien', 'A', 'Q', '', '298', false, true, '');

----------------
--- 3 ERTRAG ---
----------------

INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3', 'GESAMTLEISTUNG', 'H', 'I', '', '3', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('30', 'NETTOERLÖSE AUS LIEFERUNGEN UND LEISTUNGEN', 'H', 'I', '', '300', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('300', 'PRODUKTIONSERLÖSE', 'H', 'I', '', '300', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3000', 'Produktionserlöse', 'A', 'I', 'AR_amount:IC_income', '300', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('320', 'HANDELSERLÖSE', 'H', 'I', '', '320', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3200', 'Handelserlöse', 'A', 'I', 'AR_amount:IC_income', '320', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('340', 'DIENSTLEISTUNGSERLÖSE', 'H', 'I', '', '340', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3400', 'Dienstleistungserlöse', 'A', 'I', 'AR_amount:IC_income', '340', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('350', 'ERLÖSMINDERUNGEN AUS LIEFERUNGEN UND LEISTUNGEN', 'H', 'I', '', '350', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3500', 'Skonti LuL', 'A', 'I', 'AR_paid', '350', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('36', 'ÜBRIGER ERLÖS', 'H', 'I', '', '360', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3600', 'Nebenerlöse aus Schulungen und Workshops', 'A', 'I', 'AR_amount:IC_income', '360', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3620', 'Erlöse Untermiete', 'A', 'I', 'AR_amount:IC_income', '360', false, true, NULL);
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3680', 'Sonstige Erlöse', 'A', 'I', 'AR_amount:IC_income', '360', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3689', 'Nicht kontiert', 'A', 'I', 'AR_amount', '360', false, true, 'nichtkontierterertrag');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3699', 'Systemkonto', 'A', 'I', 'AR_amount:IC_sale:IC_income', '360', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('37', 'AKTIVIERTE EIGENLEISTUNGEN', 'H', 'I', '', '370', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3700', 'Eigenleistungen', 'A', 'I', '', '370', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3710', 'Eigenverbrauch', 'A', 'I', '', '370', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('38', 'ERLÖSMINDERUNGEN', 'H', 'I', '', '380', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3800', 'Skonti', 'A', 'I', 'AR_paid', '380', false, true, 'debitorskonto');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3801', 'Rabatte und Preisnachlässe', 'A', 'I', 'AR_paid', '380', false, true, 'debitordifferenz');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3804', 'Inkassospesen', 'A', 'I', '', '380', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3805', 'Verluste Forderungen, Veränderung Wertberichtigungen', 'A', 'I', 'AR_amount:IC_income', '380', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('39', 'BESTANDESÄNDERUNGEN AN UNFERTIGEN UND FERTIGEN ERZEUGNISSEN SOWIE AN NICHT FAKTURIERTEN DIENSTLEISTUNGEN', 'H', 'I', '', '390', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3900', 'Bestandesänderungen unfertige Erzeugnisse', 'A', 'I', '', '390', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3901', 'Bestandesänderungen fertige Erzeugnisse', 'A', 'I', '', '390', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('3904', 'Bestandesänderungen nicht fakturierte Dienstleistungen', 'A', 'I', '', '390', false, true, '');

-----------------
--- 4 AUFWAND ---
-----------------

INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('4', 'AUFWAND FÜR MATERIAL, WAREN UND DIENSTLEISTUNGEN', 'H', 'E', '', '400', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('40', 'MATERIALAUFWAND', 'H', 'E', '', '400', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('4000', 'Materialeinkauf', 'A', 'E', 'AP_amount', '400', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('42', 'HANDELSWARENAUFWAND', 'H', 'E', '', '420', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('4200', 'Einkauf Handelsware', 'A', 'E', 'AP_amount', '420', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('44', 'AUFWAND FÜR BEZOGENE DRITTLEISTUNGEN', 'H', 'E', '', '440', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('4400', 'Einkauf Drittleistung', 'A', 'E', 'AP_amount', '440', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('45', 'ENERGIEAUFWAND ZUR LEISTUNGSERSTELLUNG', 'H', 'E', '', '450', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('46', 'ÜBRIGER AUFWAND FÜR MATERIAL, HANDELSWAREN UND DIENSTLEISTUNGEN', 'H', 'E', '', '460', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('47', 'DIREKTE EINKAUFSSPESEN', 'H', 'E', '', '470', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('48', 'BESTANDESÄNDERUNGEN MATERIAL- / WARENVERLUSTE', 'H', 'E', '', '480', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('4800', 'Bestandesänderungen Handelswaren', 'A', 'E', '', '480', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('4880', 'Materialverluste', 'A', 'E', '', '480', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('49', 'EINKAUFSPREISMINDERUNGEN', 'H', 'E', '', '490', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('4999', 'Systemkonto', 'A', 'E', 'AP_amount:IC_expense:IC_cogs', '490', false, true, '');

INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5', 'PERSONALAUFWAND', 'H', 'E', '', '500', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('54', 'LOHNAUFWAND', 'H', 'E', '', '540', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5400', 'Löhne', 'A', 'E', '', '540', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5401', 'Zulagen', 'A', 'E', '', '540', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5402', 'Erfolgsbeteiligungen', 'A', 'E', '', '540', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5403', 'Provisionen', 'A', 'E', '', '540', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5405', 'Leistungen von Sozialversicherungen', 'A', 'E', 'AP_amount', '540', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('57', 'SOZIALVERSICHERUNGSAUFWAND', 'H', 'E', '', '570', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5700', 'AHV, IV, EO, ALV', 'A', 'E', 'AP_amount', '570', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5710', 'FAK', 'A', 'E', 'AP_amount', '570', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5720', 'Vorsorgeeinrichtungen', 'A', 'E', 'AP_amount', '570', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5730', 'Unfallversicherung', 'A', 'E', 'AP_amount', '570', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5740', 'Krankentaggeldversicherung', 'A', 'E', 'AP_amount', '570', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5790', 'Quellensteuer', 'A', 'E', 'AP_amount', '570', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('58', 'ÜBRIGER PERSONALAUFWAND', 'H', 'E', '', '580', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5800', 'Personalinserate', 'A', 'E', 'AP_amount', '580', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5810', 'Aus- und Weiterbildung', 'A', 'E', 'AP_amount', '580', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5820', 'Spesenentschädigung effektiv', 'A', 'E', 'AP_amount', '580', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5830', 'Spesenentschädigung pauschal', 'A', 'E', 'AP_amount', '580', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5840', 'Personalkantine', 'A', 'E', 'AP_amount', '580', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5880', 'Sonstiger Personalaufwand', 'A', 'E', 'AP_amount', '580', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5890', 'Privatanteile Personalaufwand', 'A', 'E', '', '580', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('59', 'LEISTUNGEN DRITTER', 'H', 'E', '', '590', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('5900', 'Leistungen Dritter', 'A', 'E', 'AP_amount', '590', false, true, '');

INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6', 'ÜBRIGER BETRIEBLICHER AUFWAND, ABSCHREIBUNGEN UND WERTBERICHTIGUNGEN SOWIE FINANZERGEBNIS', 'H', 'E', '', '600', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('60', 'ÜBRIGER BETRIEBLICHER AUFWAND', 'H', 'E', '', '600', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('600', 'RAUMAUFWAND', 'H', 'E', '', '600', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6000', 'Mietzins', 'A', 'E', 'AP_amount', '600', false, true, 'miete');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6001', 'Parkplatz-Miete', 'A', 'E', 'AP_amount', '600', false, true, NULL);
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6030', 'Nebenkosten', 'A', 'E', 'AP_amount', '600', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6040', 'Reinigung', 'A', 'E', 'AP_amount', '600', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6090', 'Privatanteile Raumaufwand', 'A', 'E', '', '600', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('610', 'UNTERHALT, REPARATUREN, ERSATZ (URE) LEASING MOBILE SACHANLAGEN', 'H', 'E', '', '610', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6130', 'URE Büromobiliar', 'A', 'E', 'AP_amount', '610', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6160', 'Leasing mobile Sachanlagen', 'A', 'E', 'AP_amount', '610', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('620', 'FAHRZEUG- UND TRANSPORTAUFWAND', 'H', 'E', '', '620', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6200', 'Reparaturen, Service, Reinigung Fahrzeuge', 'A', 'E', 'AP_amount', '620', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6210', 'Betriebsstoffe Fahrzeuge', 'A', 'E', 'AP_amount', '620', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6220', 'Versicherungen Fahrzeuge', 'A', 'E', 'AP_amount', '620', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6230', 'Verkehrsabgaben, Beiträge, Gebühren', 'A', 'E', 'AP_amount', '620', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6260', 'Fahrzeugleasing, Fahrzeugmieten', 'A', 'E', 'AP_amount', '620', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6270', 'Privatanteil Fahrzeugaufwand', 'A', 'E', 'AR_amount', '620', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6280', 'Transportaufwand', 'A', 'E', 'AP_amount', '620', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('630', 'SACHVERSICHERUNGEN, ABGABEN, GEBÜHREN, BEWILLIGUNGEN', 'H', 'E', '', '630', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6300', 'Sachversicherungen', 'A', 'E', 'AP_amount', '630', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6360', 'Abgaben und Gebühren', 'A', 'E', 'AP_amount', '630', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6370', 'Bewilligungen', 'A', 'E', 'AP_amount', '630', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('640', 'ENERGIE- UND ENTSORGUNGSAUFWAND', 'H', 'E', '', '640', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6400', 'Elektrizität', 'A', 'E', 'AP_amount', '640', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6460', 'Entsorgungsaufwand', 'A', 'E', 'AP_amount', '640', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('650', 'VERWALTUNGSAUFWAND', 'H', 'E', '', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6500', 'Büromaterial', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6501', 'Drucksachen', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6503', 'Fachliteratur', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6510', 'Telekommunikation', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6513', 'Porti', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6520', 'Beiträge, Spenden, Vergabungen, Trinkgelder', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6530', 'Buchführung', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6531', 'Unternehmensberatung', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6532', 'Rechtsberatung', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6540', 'Verwaltungsrat, Generalversammlung', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6542', 'Revisionsstelle', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6550', 'Gründungs-, Kapitalerhöhungs- und Organisationsaufwand', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6551', 'Inkasso- und Betreibungsaufwand', 'A', 'E', 'AP_amount', '650', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6558', 'Steuerlich nicht abzugsfähiger Verwaltungsaufwand', 'A', 'E', 'AP_amount', '650', false, true, NULL);
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('657', 'INFORMATIKAUFWAND', 'H', 'E', '', '657', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6570', 'Leasing Hardware und Software', 'A', 'E', 'AP_amount', '657', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6580', 'Lizenzen, Updates', 'A', 'E', 'AP_amount', '657', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6581', 'Hosting und Wartung', 'A', 'E', 'AP_amount', '657', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6583', 'Verbrauchsmaterial IT', 'A', 'E', 'AP_amount', '657', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6590', 'Beratung und Entwicklung IT', 'A', 'E', 'AP_amount', '657', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('660', 'WERBEAUFWAND', 'H', 'E', '', '660', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6600', 'Werbeinserate', 'A', 'E', 'AP_amount', '660', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6610', 'Werbedrucksachen, Werbematerial, Muster', 'A', 'E', 'AP_amount', '660', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6620', 'Fachmessen, Ausstellungen, Dekoration', 'A', 'E', 'AP_amount', '660', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6640', 'Reisespesen', 'A', 'E', 'AP_amount', '660', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6641', 'Kundenbetreuung', 'A', 'E', 'AP_amount', '660', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6660', 'Sponsoring', 'A', 'E', 'AP_amount', '660', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6670', 'Öffentlichkeitsarbeit, Public Relations', 'A', 'E', 'AP_amount', '660', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6680', 'Werbeberatung, Marktanalysen', 'A', 'E', 'AP_amount', '660', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('670', 'SONSTIGER BETRIEBLICHER AUFWAND', 'H', 'E', '', '670', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6700', 'Sonstiger betrieblicher Aufwand', 'A', 'E', 'AP_amount', '670', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6731', 'Bezugsteuer', 'A', 'E', 'AP_amount', '670', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6732', 'Vorsteuerkorrektur', 'A', 'E', 'AP_amount', '670', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6733', 'Vorsteuerkürzung', 'A', 'E', 'AP_amount', '670', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6799', 'Nicht kontiert', 'A', 'E', 'AP_amount', '670', false, true, 'nichtkontierteraufwand');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('68', 'ABSCHREIBUNGEN UND WERTBERICHTIGUNGEN AUF POSITIONEN DES ANLAGEVERMÖGENS', 'H', 'E', '', '680', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6800', 'Wertberichtigungen', 'A', 'E', '', '680', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6820', 'Abschreibungen', 'A', 'E', '', '680', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('69', 'FINANZAUFWAND UND FINANZERTRAG', 'H', 'E', '', '690', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('690', 'FINANZAUFWAND', 'H', 'E', '', '690', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6900', 'Zinsaufwand gegenüber Dritten', 'A', 'E', 'AP_amount', '690', false, true, 'schuldzins');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6920', 'Zinsaufwand gegenüber Beteiligten und Organen', 'A', 'E', 'AP_amount', '690', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6930', 'Zinsaufwand gegenüber Vorsorgeeinrichtungen', 'A', 'E', 'AP_amount', '690', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6940', 'Bankspesen', 'A', 'E', 'AR_paid:AP_paid', '690', false, true, 'drittspesen');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6942', 'Kursverluste', 'A', 'E', '', '690', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6943', 'Kreditkartengebühr', 'A', 'E', 'AP_amount', '690', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6944', 'Bankspesen Zahlungsverkehr, Rundungsdifferenzen', 'A', 'E', 'AP_paid', '690', false, true, 'kreditordifferenz');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('695', 'FINANZERTRAG', 'H', 'E', '', '690', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6950', 'Erträge aus flüssigen Mitteln und Wertschriften', 'A', 'E', '', '690', false, true, 'guthabenzins');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('6952', 'Kursgewinne', 'A', 'E', '', '690', false, true, '');

INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('7', 'BETRIEBSFREMDER AUFWAND UND ERTRAG', 'H', 'E', '', '700', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('700', 'ERTRAG AUS NEBENBETRIEBEN', 'H', 'E', '', '700', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('7000', 'Ertrag aus Nebenbetrieb', 'A', 'E', '', '700', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('701', 'AUFWAND AUS NEBENBETRIEBEN', 'H', 'E', '', '701', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('7010', 'Aufwand aus Nebenbetrieb', 'A', 'E', '', '701', false, true, '');

INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8', 'AUSSERORDENTLICHER, EINMALIGER ODER PERIODENFREMDER AUFWAND UND ERTRAG SOWIE DIREKTE STEUERN', 'H', 'E', '', '800', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('80', 'AUSSERORDENTLICHER, EINMALIGER ODER PERIODENFREMDER AUFWAND UND ERTRAG', 'H', 'E', '', '800', false, false, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('800', 'BETRIEBSFREMDER AUFWAND', 'H', 'E', '', '800', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8000', 'Betriebsfremder Aufwand', 'A', 'E', '', '800', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('810', 'BETRIEBSFREMDER ERTRAG', 'H', 'E', '', '810', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8100', 'Betriebsfremder Ertrag', 'A', 'E', '', '810', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('850', 'AUSSERORDENTLICHER AUFWAND', 'H', 'E', '', '850', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8500', 'Ausserordentlicher Aufwand', 'A', 'E', 'AP_amount', '850', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('851', 'AUSSERORDENTLICHER ERTRAG', 'H', 'E', '', '851', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8510', 'Ausserordentlicher Ertrag', 'A', 'E', 'AR_amount:AP_amount', '851', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('860', 'EINMALIGER AUFWAND', 'H', 'E', '', '860', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8600', 'Einmaliger Aufwand', 'A', 'E', '', '860', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('861', 'EINMALIGER ERTRAG', 'H', 'E', '', '861', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8610', 'Einmaliger Ertrag', 'A', 'E', '', '861', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('870', 'PERIODENFREMDER AUFWAND', 'H', 'E', '', '870', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8700', 'Periodenfremder Aufwand', 'A', 'E', '', '870', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('871', 'PERIODENFREMDER ERTRAG', 'H', 'E', '', '871', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8710', 'Periodenfremder Ertrag', 'A', 'E', '', '871', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('89', 'DIREKTE STEUERN', 'H', 'E', '', '890', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8900', 'Kantons- und Gemeindesteuern', 'A', 'E', 'AP_amount', '890', false, true, '');
INSERT INTO chart (accno, description, charttype, category, link, gifi_accno, contra, allow_gl, symbol_link) VALUES ('8901', 'Direkte Bundessteuern', 'A', 'E', 'AP_amount', '890', false, true, '');

---

--------------
--- 5 GIFI ---
--------------

DELETE FROM gifi;

INSERT INTO gifi (accno, description) VALUES ('1', 'AKTIVEN');
INSERT INTO gifi (accno, description) VALUES ('2', 'PASSIVEN');
INSERT INTO gifi (accno, description) VALUES ('3', 'GESAMTLEISTUNG');
INSERT INTO gifi (accno, description) VALUES ('4', 'AUFWAND FÜR MATERIAL, WAREN UND DIESTLEISTUNGEN');
INSERT INTO gifi (accno, description) VALUES ('5', 'PERSONALAUFWAND');
INSERT INTO gifi (accno, description) VALUES ('6', 'ÜBRIGER BETRIEBLICHER AUFWAND, ABSCHREIBUNGEN UND WERTBERICHTIGUNGEN SOWIE FINANZERGEBNIS');
INSERT INTO gifi (accno, description) VALUES ('7', 'BETRIEBLICHER NEBENERFOLG ');
INSERT INTO gifi (accno, description) VALUES ('8', 'AUSSERORDENTLICHER UND BETRIEBSFREMDER ERFOLG, STEUERN');
INSERT INTO gifi (accno, description) VALUES ('100', 'Flüssige Mittel');
INSERT INTO gifi (accno, description) VALUES ('106', 'Kurzfristig gehaltene Aktiven mit Börsenkurs');
INSERT INTO gifi (accno, description) VALUES ('109', 'Transferkonto');
INSERT INTO gifi (accno, description) VALUES ('110', 'Forderungen aus Lieferungen und Leistungen gegenüber Dritten');
INSERT INTO gifi (accno, description) VALUES ('111', 'Forderungen aus Lieferungen und Leistungen gegenüber Beteiligungen');
INSERT INTO gifi (accno, description) VALUES ('112', 'Forderungen aus Lieferungen und Leistungen gegenüber Beteiligten und Organen');
INSERT INTO gifi (accno, description) VALUES ('114', 'Übrige kurzfristige Forderungen gegenüber Dritten');
INSERT INTO gifi (accno, description) VALUES ('115', 'Übrige kurzfristige Forderungen gegenüber Beteiligungen');
INSERT INTO gifi (accno, description) VALUES ('116', 'Übrige kurzfristige Forderungen gegenüber Beteiligten und Organen');
INSERT INTO gifi (accno, description) VALUES ('117', 'Kurzfristige Forderungen gegenüber staatlichen Stellen');
INSERT INTO gifi (accno, description) VALUES ('118', 'Kurzfristige Forderungen gegenüber Sozialversicherungen');
INSERT INTO gifi (accno, description) VALUES ('119', 'Sonstige kurzfristige Forderungen');
INSERT INTO gifi (accno, description) VALUES ('120', 'Vorräte und nicht fakturierte Dienstleistungen');
INSERT INTO gifi (accno, description) VALUES ('130', 'Aktive Rechnungsabgrenzungen');
INSERT INTO gifi (accno, description) VALUES ('140', 'Finanzanlagen');
INSERT INTO gifi (accno, description) VALUES ('144', 'Langfristige Forderungen gegenüber Dritten');
INSERT INTO gifi (accno, description) VALUES ('145', 'Langfristige Forderungen gegenüber Beteiligungen');
INSERT INTO gifi (accno, description) VALUES ('146', 'Langfristige Forderungen gegenüber Beteiligten und Organen');
INSERT INTO gifi (accno, description) VALUES ('148', 'Beteiligungen');
INSERT INTO gifi (accno, description) VALUES ('150', 'Mobile Sachanlagen');
INSERT INTO gifi (accno, description) VALUES ('160', 'Immobile Sachanlagen');
INSERT INTO gifi (accno, description) VALUES ('170', 'Immaterielle Werte');
INSERT INTO gifi (accno, description) VALUES ('180', 'Nicht einbezahltes Grundkapital');
INSERT INTO gifi (accno, description) VALUES ('200', 'Verbindlichkeiten aus Lieferungen und Leistungen');
INSERT INTO gifi (accno, description) VALUES ('201', 'VERBINDLICHKEITEN AUS LIEFERUNGEN UND LEISTUNGEN GEGENÜBER BETEILIGTEN UND ORGANEN');
INSERT INTO gifi (accno, description) VALUES ('202', 'VERBINDLICHKEITEN AUS LIEFERUNGEN UND LEISTUNGEN GEGENÜBER BETEILIGUNGEN');
INSERT INTO gifi (accno, description) VALUES ('203', 'Erhaltene Anzahlungen von Dritten');
INSERT INTO gifi (accno, description) VALUES ('210', 'Kurzfristige verzinsliche Verbindlichkeiten');
INSERT INTO gifi (accno, description) VALUES ('214', 'Übrige kurzfristige verzinsliche Verbindlichkeiten gegenüber Dritten');
INSERT INTO gifi (accno, description) VALUES ('215', 'Kurzfristige verzinsliche Verbindlichkeiten gegenüber Beteiligungen');
INSERT INTO gifi (accno, description) VALUES ('216', 'Kurzfristige verzinsliche Verbindlichkeiten gegenüber Beteiligten und Organen');
INSERT INTO gifi (accno, description) VALUES ('220', 'Kurzfristige Verbindlichkeiten gegenüber staatlichen Stellen');
INSERT INTO gifi (accno, description) VALUES ('221', 'Übrige kurzfristige Verbindlichkeiten gegenüber Dritten (unverzinslich)');
INSERT INTO gifi (accno, description) VALUES ('225', 'Übrige kurzfristige Verbindlichkeiten gegenüber Beteiligungen (unverzinslich)');
INSERT INTO gifi (accno, description) VALUES ('226', 'Übrige kurzfristige Verbindlichkeiten gegenüber Beteiligten und Organen (unverzinslich)');
INSERT INTO gifi (accno, description) VALUES ('227', 'Übrige kurzfristige Verbindlichkeiten gegenüber Sozialversicherungen');
INSERT INTO gifi (accno, description) VALUES ('230', 'Passive Rechnungsabgrenzung und kurzfristige Rückstellungen');
INSERT INTO gifi (accno, description) VALUES ('240', 'Langfristige verzinsliche Verbindlichkeiten');
INSERT INTO gifi (accno, description) VALUES ('245', 'Übrige langfristige verzinsliche Verbindlichkeiten gegenüber Dritten');
INSERT INTO gifi (accno, description) VALUES ('247', 'Langfristige verzinsliche Verbindlichkeiten gegenüber Beteiligungen');
INSERT INTO gifi (accno, description) VALUES ('248', 'Langfristige verzinsliche Verbindlichkeiten gegenüber Beteiligten und Organen');
INSERT INTO gifi (accno, description) VALUES ('250', 'Übrige langfristige Verbindlichkeiten gegenüber Dritten (unverzinslich)');
INSERT INTO gifi (accno, description) VALUES ('255', 'Übrige langfristige Verbindlichkeiten gegenüber Beteiligungen (unverzinslich)');
INSERT INTO gifi (accno, description) VALUES ('256', 'Übrige langfristige Verbindlichkeiten gegenüber Beteiligten und Organen (unverzinslich)');
INSERT INTO gifi (accno, description) VALUES ('260', 'Rückstellungen sowie vom Gesetz vorgesehenen ähnlichen Positionen');
INSERT INTO gifi (accno, description) VALUES ('280', 'Kapital');
INSERT INTO gifi (accno, description) VALUES ('282', 'Kapitaleinlagen und Kapitalrücklage');
INSERT INTO gifi (accno, description) VALUES ('285', 'Privat');
INSERT INTO gifi (accno, description) VALUES ('289', 'Jahresgewinn oder Jahresverlust');
INSERT INTO gifi (accno, description) VALUES ('290', 'Reserven und Jahresgewinn oder Jahresverlust');
INSERT INTO gifi (accno, description) VALUES ('295', 'GESETZLICHE GEWINNRESERVE');
INSERT INTO gifi (accno, description) VALUES ('296', 'FREIWILLIGE GEWINNRESERVEN');
INSERT INTO gifi (accno, description) VALUES ('297', 'Bilanzgewinn oder Bilanzverlust');
INSERT INTO gifi (accno, description) VALUES ('298', 'Eigene Kapitalanteile');
INSERT INTO gifi (accno, description) VALUES ('300', 'Produktionserlöse');
INSERT INTO gifi (accno, description) VALUES ('320', 'Handelserlöse');
INSERT INTO gifi (accno, description) VALUES ('340', 'Dienstleistungserlöse');
INSERT INTO gifi (accno, description) VALUES ('350', 'Erlösminderungen aus Lieferungen und Leistungen');
INSERT INTO gifi (accno, description) VALUES ('360', 'Übrige Erlöse aus Lieferungen und Leistungen');
INSERT INTO gifi (accno, description) VALUES ('370', 'Eigenleistungen und Eigenverbrauch');
INSERT INTO gifi (accno, description) VALUES ('380', 'Erlösminderungen');
INSERT INTO gifi (accno, description) VALUES ('390', 'Bestandesänderungen an unfertigen und fertigen Erzeugnissen sowie an nicht fakturierten Dienstleistungen');
INSERT INTO gifi (accno, description) VALUES ('400', 'Materialaufwand');
INSERT INTO gifi (accno, description) VALUES ('420', 'Handelswarenaufwand');
INSERT INTO gifi (accno, description) VALUES ('440', 'Aufwand für bezogene Drittleistungen');
INSERT INTO gifi (accno, description) VALUES ('450', 'Energieaufwand zur Leistungserstellung');
INSERT INTO gifi (accno, description) VALUES ('460', 'Übriger Aufwand für Material, Handelswaren und Dienstleistungen');
INSERT INTO gifi (accno, description) VALUES ('470', 'Direkte Einkaufsspesen');
INSERT INTO gifi (accno, description) VALUES ('480', 'Bestandesveränderungen und Material- / Warenverluste');
INSERT INTO gifi (accno, description) VALUES ('490', 'Einkaufspreisminderung');
INSERT INTO gifi (accno, description) VALUES ('500', 'Personalaufwand');
INSERT INTO gifi (accno, description) VALUES ('540', 'Lohnaufwand');
INSERT INTO gifi (accno, description) VALUES ('570', 'Sozialversicherungsaufwand');
INSERT INTO gifi (accno, description) VALUES ('580', 'Übriger Personalaufwand');
INSERT INTO gifi (accno, description) VALUES ('590', 'Leistungen Dritter');
INSERT INTO gifi (accno, description) VALUES ('600', 'Raumaufwand');
INSERT INTO gifi (accno, description) VALUES ('610', 'Unterhalt, Reparaturen, Ersatz (URE) Leasing Mobile Sachanlagen');
INSERT INTO gifi (accno, description) VALUES ('620', 'Fahrzeug- und Transportaufwand');
INSERT INTO gifi (accno, description) VALUES ('630', 'Sachversicherungen, Abgaben, Gebühren, Bewilligungen');
INSERT INTO gifi (accno, description) VALUES ('640', 'Energie- und Entsorgungsaufwand');
INSERT INTO gifi (accno, description) VALUES ('650', 'Verwaltungsaufwand');
INSERT INTO gifi (accno, description) VALUES ('657', 'Informatikaufwand');
INSERT INTO gifi (accno, description) VALUES ('660', 'Werbeaufwand');
INSERT INTO gifi (accno, description) VALUES ('670', 'Sonstiger betrieblicher Aufwand');
INSERT INTO gifi (accno, description) VALUES ('680', 'Abschreibungen und Wertberichtigungen');
INSERT INTO gifi (accno, description) VALUES ('690', 'Finanzaufwand und Finanzertrag');
INSERT INTO gifi (accno, description) VALUES ('695', 'Finanzertrag');
INSERT INTO gifi (accno, description) VALUES ('700', 'Ertrag aus Nebenbetrieben');
INSERT INTO gifi (accno, description) VALUES ('701', 'Aufwand aus Nebenbetrieb');
INSERT INTO gifi (accno, description) VALUES ('750', 'Erfolg aus betrieblicher Liegenschaft');
INSERT INTO gifi (accno, description) VALUES ('751', 'Aufwand aus betrieblicher Liegenschaft');
INSERT INTO gifi (accno, description) VALUES ('800', 'Betriebsfremder Aufwand');
INSERT INTO gifi (accno, description) VALUES ('810', 'Betriebsfremder Ertrag');
INSERT INTO gifi (accno, description) VALUES ('850', 'Ausserordentlicher Aufwand');
INSERT INTO gifi (accno, description) VALUES ('851', 'Ausserordentlicher Ertrag');
INSERT INTO gifi (accno, description) VALUES ('860', 'Einmaliger Aufwand');
INSERT INTO gifi (accno, description) VALUES ('861', 'Einmaliger Ertrag');
INSERT INTO gifi (accno, description) VALUES ('870', 'Periodenfremder Aufwand');
INSERT INTO gifi (accno, description) VALUES ('871', 'Periodenfremder Ertrag');
INSERT INTO gifi (accno, description) VALUES ('890', 'Direkte Steuern');

-------------
--- 6 TAX ---
-------------

DELETE FROM tax;

INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (32, (SELECT id FROM chart WHERE accno = '11700'), 0.081, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (33, (SELECT id FROM chart WHERE accno = '11710'), 1, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (34, (SELECT id FROM chart WHERE accno = '11711'), 1, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (35, (SELECT id FROM chart WHERE accno = '11720'), 0.026, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (36, (SELECT id FROM chart WHERE accno = '11730'), 0.081, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (37, (SELECT id FROM chart WHERE accno = '11740'), 0.038, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (38, (SELECT id FROM chart WHERE accno = '11750'), 0.026, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (39, (SELECT id FROM chart WHERE accno = '11760'), 0.081, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (40, (SELECT id FROM chart WHERE accno = '22010'), 0.081, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (41, (SELECT id FROM chart WHERE accno = '22020'), 0.038, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (42, (SELECT id FROM chart WHERE accno = '22030'), 0.026, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (43, (SELECT id FROM chart WHERE accno = '22040'), 0.081, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (44, (SELECT id FROM chart WHERE accno = '22050'), 0, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (45, (SELECT id FROM chart WHERE accno = '22051'), 0, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (46, (SELECT id FROM chart WHERE accno = '22052'), 0, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (47, (SELECT id FROM chart WHERE accno = '22053'), 0, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (48, (SELECT id FROM chart WHERE accno = '22054'), 0, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (49, (SELECT id FROM chart WHERE accno = '22055'), 0, 'CHE-XXX.XXX.XXX MWST', NULL);
INSERT INTO tax (id, chart_id, rate, taxnumber, validto) VALUES (50, (SELECT id FROM chart WHERE accno = '22060'), 0, 'CHE-XXX.XXX.XXX MWST', NULL);

------------------
--- 7 DEFAULTS ---
------------------
DELETE FROM defaults;

INSERT INTO defaults (fldname, fldvalue) VALUES ('inventory_accno_id', (SELECT id FROM chart WHERE accno = '1280'));
INSERT INTO defaults (fldname, fldvalue) VALUES ('income_accno_id', (SELECT id FROM chart WHERE accno = '3400'));
INSERT INTO defaults (fldname, fldvalue) VALUES ('expense_accno_id', (SELECT id FROM chart WHERE accno = '4200'));
INSERT INTO defaults (fldname, fldvalue) VALUES ('fxgain_accno_id', (SELECT id FROM chart WHERE accno = '6952'));
INSERT INTO defaults (fldname, fldvalue) VALUES ('fxloss_accno_id', (SELECT id FROM chart WHERE accno = '6942'));
INSERT INTO defaults (fldname, fldvalue) VALUES ('weightunit', 'kg');
INSERT INTO defaults (fldname, fldvalue) VALUES ('precision', '2');
INSERT INTO DEFAULTS (fldname, fldvalue) VALUES ('cdt', '1');
INSERT INTO defaults (fldname, fldvalue) VALUES ('glnumber','X-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('sinumber','R-999');
INSERT INTO defaults (fldname, fldvalue) VALUES ('vinumber','EB-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('batchnumber','V-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('vouchernumber','B-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('sonumber','AB-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('ponumber','E-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('sqnumber','O-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('rfqnumber','EO-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('partnumber','ART-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('employeenumber','MA-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('customernumber','KD-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('vendornumber','L-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('projectnumber','P-0');
INSERT INTO defaults (fldname, fldvalue) VALUES ('audittrail','1');
INSERT INTO defaults (fldname, fldvalue) VALUES ('linetax', '1');
--------------------
--- 8 CURRENCIES ---
--------------------

DELETE FROM curr;

INSERT INTO curr (rn, curr, prec) VALUES (1,'CHF',2);
INSERT INTO curr (rn, curr, prec) VALUES (2,'EUR',2);
INSERT INTO curr (rn, curr, prec) VALUES (3,'USD',2);
INSERT INTO curr (rn, curr, prec) VALUES (4,'GBP',2);
INSERT INTO curr (rn, curr, prec) VALUES (5,'JPY',2);
INSERT INTO curr (rn, curr, prec) VALUES (6,'CAD',2);
INSERT INTO curr (rn, curr, prec) VALUES (7,'AUD',2);
INSERT INTO curr (rn, curr, prec) VALUES (8,'CNY',2);
INSERT INTO curr (rn, curr, prec) VALUES (9,'SGD',2);
INSERT INTO curr (rn, curr, prec) VALUES (10,'HKD',2);
INSERT INTO curr (rn, curr, prec) VALUES (11,'SEK',2);
INSERT INTO curr (rn, curr, prec) VALUES (12,'DKK',2);
INSERT INTO curr (rn, curr, prec) VALUES (13,'NOK',2);
INSERT INTO curr (rn, curr, prec) VALUES (14,'PLN',2);
INSERT INTO curr (rn, curr, prec) VALUES (15,'RUB',2);
INSERT INTO curr (rn, curr, prec) VALUES (16,'RSD',2);
INSERT INTO curr (rn, curr, prec) VALUES (17,'TRY',2);

