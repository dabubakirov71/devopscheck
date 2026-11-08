"""
Server-rendered sparklines.

Drawn as inline SVG rather than pulled from a charting CDN: one less external
script on every page, nothing to block, and no third-party dependency in a
product whose whole job is telling people to pin their supply chain.
"""

WIDTH = 100.0   # viewBox units; the SVG scales to its container
HEIGHT = 30.0
PAD = 2.0


def _num(value):
    """SVG coordinate as text — never as a number a locale can reformat."""
    text = f'{float(value):.2f}'.rstrip('0').rstrip('.')
    return text or '0'


def series(values, width=WIDTH, height=HEIGHT, pad=PAD, y_min=0, y_max=100):
    """
    Turn a list of numbers into the geometry a sparkline needs.

    Returns points for the line, a closed path for the area fill, and the
    coordinates of the final point so it can be emphasised.
    """
    clean = [v for v in values if v is not None]
    if not clean:
        return None

    span = max(1e-9, (y_max - y_min))
    n = len(clean)
    step = (width - 2 * pad) / max(1, n - 1) if n > 1 else 0

    coords = []
    for i, value in enumerate(clean):
        x = pad + i * step if n > 1 else width / 2
        ratio = (min(y_max, max(y_min, value)) - y_min) / span
        y = height - pad - ratio * (height - 2 * pad)
        coords.append((round(x, 2), round(y, 2)))

    line = ' '.join(f'{x},{y}' for x, y in coords)
    first_x, _first_y = coords[0]
    last_x, last_y = coords[-1]
    area = f'M{first_x},{height} L{line.replace(" ", " L")} L{last_x},{height} Z'

    # Geometry leaves here as text on purpose. A float rendered through a
    # template under a locale that uses a decimal comma comes out as "100,0",
    # and `viewBox="0 0 100,0 30,0"` makes the browser drop the whole chart —
    # which is exactly what every Russian reader used to see.
    return {
        'points': line,
        'area': area,
        # Per-point geometry, so the chart can carry a hover target and a dot at
        # each reading. A line chart with no way to read a value is a decoration.
        'coords': [
            {
                'x': _num(x), 'y': _num(y), 'value': v,
                # A column around each reading, so the hover target is the width
                # of the slot rather than the width of the dot. Clamped to the
                # canvas: the first and last columns are half-columns, and an
                # unclamped one hangs off the edge of the chart.
                'hit_x': _num(max(0.0, x - (step or width) / 2)),
                'hit_w': _num(
                    min(width, x + (step or width) / 2)
                    - max(0.0, x - (step or width) / 2)
                ),
            }
            for (x, y), v in zip(coords, clean)
        ],
        'last_x': _num(last_x),
        'last_y': _num(last_y),
        'first': clean[0],
        'last': clean[-1],
        'min': min(clean),
        'max': max(clean),
        'count': n,
        'width': _num(width),
        'height': _num(height),
    }


def color_for(score):
    if score is None:
        return 'var(--dim)'
    if score >= 80:
        return '#00cc6a'
    if score >= 60:
        return 'var(--blue)'
    if score >= 40:
        return 'var(--amber)'
    return 'var(--red)'
