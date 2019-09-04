package org.wildfly.security.ssl;

import java.security.cert.Certificate;
import java.security.cert.PKIXReason;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.CertPathValidatorException;
import javax.security.auth.x500.X500Principal;

public class MaxCertPathChecker extends PKIXCertPathChecker {
    private int maxPathLength;
    private Set<String> supportedExts;
    private int i;

    MaxCertPathChecker(int maxPathLength) {
        this.maxPathLength = maxPathLength;
    }

    /*
     * Initialize checker
     */
    public void init(boolean forward) {
        i = 0;
    }

    @Override
    public boolean isForwardCheckingSupported() {
        return false;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        if (supportedExts == null) {
            supportedExts = new HashSet<String>(2);
            supportedExts = Collections.unmodifiableSet(supportedExts);
        }
        return supportedExts;
    }

    /*
     * Check certificate for presence of Netscape's
     * private extension
     * with OID "2.16.840.1.113730.1.1"
     */
    public void check(Certificate cert,
                      Collection unresolvedCritExts)
            throws CertPathValidatorException {
        X509Certificate currCert = (X509Certificate) cert;
        i++;
        checkBasicConstraints(currCert);
    }
    private void checkBasicConstraints(X509Certificate currCert)
            throws CertPathValidatorException {

        int pathLenConstraint = -1;
        if (currCert.getVersion() < 3) {    // version 1 or version 2
            if (i == 1) {
                X500Principal subject = currCert.getSubjectX500Principal();
                X500Principal issuer = currCert.getIssuerX500Principal();
                if (subject.equals(issuer)) {
                    pathLenConstraint = Integer.MAX_VALUE;
                }
            }
        } else {
            pathLenConstraint = currCert.getBasicConstraints();
        }

        if (pathLenConstraint == -1) {
            pathLenConstraint = maxPathLength;
        }
        X500Principal subject = currCert.getSubjectX500Principal();
        X500Principal issuer = currCert.getIssuerX500Principal();
        if (!subject.equals(issuer)) {
            if (pathLenConstraint < i) {
                throw new CertPathValidatorException
                        ("check failed: pathLenConstraint violated - "
                                + "this cert must be the last cert in the "
                                + "certification path", null, null, -1,
                                PKIXReason.PATH_TOO_LONG);
            }
        }
        if (pathLenConstraint < maxPathLength)
            maxPathLength = pathLenConstraint;

    }
}
