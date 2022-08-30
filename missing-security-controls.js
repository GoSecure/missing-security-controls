var Weight = {
    AV: {
        N: 0.85,
        A: 0.62,
        L: 0.55,
        P: 0.2
    },
    AC: {
        H: 0.44,
        L: 0.77
    },
    PR: {
        U: {
            N: 0.85,
            L: 0.62,
            H: 0.27
        },
        // These values are used if Scope is Unchanged
        C: {
            N: 0.85,
            L: 0.68,
            H: 0.5
        }
    },
    // These values are used if Scope is Changed
    UI: {
        N: 0.85,
        R: 0.62
    },
    S: {
        U: 6.42,
        C: 7.52
    }

};

function calculate(element) {
    var cvssVersion = "3.1";
    var exploitabilityCoefficient = 8.22;
    var scopeCoefficient = 1.08;

    var p;
    var val = {}, metricWeight = {};
    try {
      var inputs = $(element).parent().parent().parent().find('input[type="radio"]');
      inputs.each(function () {
        if (this.checked) {
          val[$(this).attr("data-field").toUpperCase()] = $(this).attr("data-value").toUpperCase();
          if (typeof val[$(this).attr("data-field").toUpperCase()] === "undefined" || val[$(this).attr("data-field").toUpperCase()] === null) {
              return "?";
          }
          metricWeight[$(this).attr("data-field").toUpperCase()] = Weight[$(this).attr("data-field").toUpperCase()][val[$(this).attr("data-field").toUpperCase()]];
        }
      });
    } catch (err) {
        return err; // TODO: need to catch and return sensible error value & do a better job of specifying *which* parm is at fault.
    }
    
    metricWeight.PR = Weight.PR[val.S][val.PR];
    //
    // CALCULATE THE CVSS BASE SCORE
    //
    var roundUp1 = function Roundup(input) {
        var int_input = Math.round(input * 100000);
        if (int_input % 10000 === 0) {
            return int_input / 100000
        } else {
            return (Math.floor(int_input / 10000) + 1) / 10
        }
    };
    try {
    var baseScore, exploitability;
    var exploitabalitySubScore = exploitabilityCoefficient * metricWeight.AV * metricWeight.AC * metricWeight.PR * metricWeight.UI;
    if (val.S === 'U') {
        baseScore = roundUp1(Math.min(exploitabalitySubScore, 10));
    } else {
        baseScore = roundUp1(Math.min(exploitabalitySubScore * scopeCoefficient, 10));
    }

    return baseScore.toFixed(1);
    } catch (err) {
        return err;
    }
};