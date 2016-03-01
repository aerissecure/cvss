# cvss
CVSS library for working with CVSS version 2 scores and base vectors

## Usage

Easily parse base vector components from a CVSS2 string:

    In []: from cvss import cvss
    In []: bv = cvss.BaseVector('AV:N/AC:L/Au:N/C:N/I:N/A:P')
    In []: bv.av
    Out[]: 'N'
    In []: bv.au
    Out[]: 'N'

Or constuct an instance of `BaseVector` from the components:

    In []: bv = cvss.from_base_metrics('n', 'l', 'n', 'n', 'p', 'c')

Test for validity:

    In []: cvss.valid_vector('AV:N/AC:L/Au:N/C:N/I:N/A:H')
    Out[]: False

Calculate the base score:

    In []: bv.base_score
    Out[]: Decimal('5.0')

Calculate the NVD severity based on the base score:

    In []: bv.severity
    Out[]: 'Medium'
