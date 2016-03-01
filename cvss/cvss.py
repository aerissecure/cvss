"""
A Series of tools for working with CVSS version 2 vectors.

"""
__version_info__ = ('4', '0')
__version__ = '.'.join(__version_info__)

import re
from decimal import Decimal as D

vector_pattern = ('AV:(?P<av>(L|A|N){1})/AC:(?P<ac>(H|M|L){1})/'
                  'Au:(?P<au>(M|S|N){1})/C:(?P<ci>(N|P|C){1})/'
                  'I:(?P<ii>(N|P|C){1})/A:(?P<ai>(N|P|C){1})')
vector_regex = re.compile(vector_pattern, re.I)
vector_template = 'AV:{0}/AC:{1}/Au:{2}/C:{3}/I:{4}/A:{5}'
base_vector_lookup = {
    'av': {
            'L':D('0.395'),
            'A':D('0.646'),
            'N':D('1.0')
            },
    'ac': {
            'H':D('0.35'),
            'M':D('0.61'),
            'L':D('0.71')
            },
    'au': {
            'M':D('0.45'),
            'S':D('0.56'),
            'N':D('0.704')
            },
    'ci': {
            'N':D('0.0'),
            'P':D('0.275'),
            'C':D('0.660')
            },
    'ii': {
            'N':D('0.0'),
            'P':D('0.275'),
            'C':D('0.660')
            },
    'ai': {
            'N':D('0.0'),
            'P':D('0.275'),
            'C':D('0.660')
            },
    }

def nvd_severity(score):
    """
    Receive cvss base score as a string, decimal, or
    int and return the NVD vulnerability severity rating.
    Low:    (0.0-3.9)
    Medium: (4.0-6.9)
    High:   (7.0-10.0)
    """
    base_score = D(score)
    if base_score < D('4.0'):
        return 'Low'
    elif D('4.0') <= base_score < D('7.0'):
        return 'Medium'
    elif D('7.0') <= base_score:
        return 'High'

def valid_vector(vector):
    """Determines if vector is valid. Case insensitive."""
    if vector_regex.search(vector):
        return True
    else:
        return False

def format_vector(vector, prefix='CVSS2#'):
    """Prefix vector and capitalize all appropriate letters"""
    vdict = vector_regex.search(vector).groupdict()
    return (prefix.upper() +
            'AV:' + vdict['av'] + '/' +
            'AC:' + vdict['ac'] + '/' +
            'Au:' + vdict['au'] + '/' +
            'C:' + vdict['ci'] + '/' +
            'I:' + vdict['ii'] + '/' +
            'A:' + vdict['ai'])

## make generic cvss2 vector class
class BaseVector:
    """
    Recieves a valid CVSS2 Base vector as input. Once the
    object is instantiated you can access each metric value,
    calculate the base score, find the NVD severity rating, and find
    its severity level along with other methods.

    If you need to determine if a vector is valid, do so before
    instantiating this class by using the valid_vector function.
    """

    def __init__(self, vector, prefix='CVSS2#'):
        self.vector = format_vector(vector)
        metrics = vector_regex.search(vector).groupdict()
        self.av = metrics['av'] # access vector
        self.ac = metrics['ac'] # access complexity
        self.au = metrics['au'] # authentication
        self.ci = metrics['ci'] # confidentiality impact
        self.ii = metrics['ii'] # integrity impact
        self.ai = metrics['ai'] # availability impact

    def __eq__(self, base_vector):
        """overwrite default "==" comparison."""
        return self.vector == base_vector.vector

    @property
    def purely_dos(self):
        """
        For PCI ASV use only. Returns True if the vector indicates
        the vulnerability is purely DoS, i.e. confidentiality and
        integrity impact are 'None'.
        """
        if self.ci == self.ii == 'N' and self.ai != 'N':
            return True
        else:
            return False

    @property
    def severity(self):
        """
        Return the NVD vulnerability severity rating.
        """
        return nvd_severity(self.base_score)

    @property
    def base_score(self):
        """
        Calculate the CVSS Base Score.
        Formual found here:
        http://www.first.org/cvss/cvss-guide.html#i3.2.1
        """
        avscore = base_vector_lookup['av'][self.av]
        acscore = base_vector_lookup['ac'][self.ac]
        auscore = base_vector_lookup['au'][self.au]
        ciscore = base_vector_lookup['ci'][self.ci]
        iiscore = base_vector_lookup['ii'][self.ii]
        aiscore = base_vector_lookup['ai'][self.ai]
        total_impact = D('10.41')*(1-(1-ciscore)*(1-iiscore)*(1-aiscore))

        def impact_calc(impact):
            if impact == 0:
                return 0
            else:
                return D('1.176')

        exploitability = 20*avscore*acscore*auscore
        base_score = (((D('0.6')*total_impact) +
                      (D('0.4')*exploitability) - D('1.5')
                     )*impact_calc(total_impact)).quantize(D('1.0'))
        return base_score


def from_base_metrics(av, ac, au, ci, ii, ai, prefix='CVSS2#'):
    """
    Receives base metric values and returns a BaseVector.
    Input metric parameter values in the same order as a found in
    a valid vector:
    (av, ac, au, ci, ii, ai)

    These correspond to the following:
    av = access vector
    ac = access complexity
    au = authentication
    ci = confidentiality impact
    ii = integrity impact
    ai = availability impact

    These parameters will accept any case-insensitive
    word as long as the first letter is valid.
    """
    vector = vector_template.format(av[0].upper(),
                                    ac[0].upper(),
                                    au[0].upper(),
                                    ci[0].upper(),
                                    ii[0].upper(),
                                    ai[0].upper())
    return BaseVector(vector)
