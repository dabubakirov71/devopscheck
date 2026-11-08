"""
Numbers the site states about itself — one place, so pages cannot disagree.

The landing page once said "~3s per scan", "about five seconds" and "30
seconds" at the same time, and "30+ checks in 8 categories" next to a report
showing 15. Every template reads these through the `site_facts` context
processor; `SiteFactsTest` keeps CHECK_COUNT equal to what the engine runs.
"""
from app.checks import CATEGORIES

#: Distinct check ids the engine can emit (see SiteFactsTest for the source).
CHECK_COUNT = 58
#: Scored categories (hygiene is shown but not a category of the score).
CATEGORY_COUNT = len(CATEGORIES)
#: A typical public scan, measured on production 2026-09-27: 3–6 s.
SCAN_SECONDS = 5
