-- Google's colour for a calendar and whether the person shows it in Google Calendar.
-- Existing rows read as unselected and uncoloured until their next discovery, within five minutes.
ALTER TABLE calendars ADD COLUMN color TEXT
  CHECK (
    color IS NULL
    OR color GLOB '#[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'
  );
ALTER TABLE calendars ADD COLUMN is_selected INTEGER NOT NULL DEFAULT 0
  CHECK (is_selected IN (0, 1));
