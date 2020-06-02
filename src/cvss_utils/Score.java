package cvss_utils;
/**
 * Defines a Score object that defines base, impact, and exploitability scores.
 *
 * @author Steve Springett
 * @since 1.0.0
 */
public class Score {

    private double baseScore;
    private double impactSubScore;
    private double exploitabilitySubScore;
    private double temporalScore;

    public Score(double baseScore, double impactSubScore, double exploitabilitySubScore) {
        this(baseScore, impactSubScore, exploitabilitySubScore, -1);
    }

    public Score(double baseScore, double impactSubScore, double exploitabilitySubScore, double temporalScore) {
        this.baseScore = baseScore;
        this.impactSubScore = impactSubScore;
        this.exploitabilitySubScore = exploitabilitySubScore;
        this.temporalScore = temporalScore;
    }

    /**
     * Returns the base score.
     * @return the base score
     */
    public double getBaseScore() {
        return baseScore;
    }

    /**
     * Returns the impact subscore.
     * @return the impact subscore
     */
    public double getImpactSubScore() {
        return impactSubScore;
    }

    /**
     * Returns the exploitability subscore.
     * @return the exploitability subscore
     */
    public double getExploitabilitySubScore() {
        return exploitabilitySubScore;
    }

    /**
     * Returns the temporal subscore.
     * @return the temporal subscore
     */
    public double getTemporalScore() {
        return temporalScore;
    }
}