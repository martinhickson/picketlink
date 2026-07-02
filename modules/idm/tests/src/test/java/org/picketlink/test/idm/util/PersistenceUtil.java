package org.picketlink.test.idm.util;

import org.hibernate.jpa.HibernatePersistenceProvider;

import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Persistence;
import jakarta.persistence.spi.PersistenceProvider;
import jakarta.persistence.spi.PersistenceProviderResolver;
import jakarta.persistence.spi.PersistenceProviderResolverHolder;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Pedro Igor
 */
public final class PersistenceUtil {

    public static final String TEST_JPA_ECLIPSELINK_PROVIDER = "test.idm.jpa.eclipselink.provider";

    static {
        PersistenceProviderResolverHolder.setPersistenceProviderResolver(new PersistenceProviderResolver() {
            @Override
            public List<PersistenceProvider> getPersistenceProviders() {
                ArrayList<PersistenceProvider> providers = new ArrayList<PersistenceProvider>();

                String enableEclipseLinkProvider = System.getProperty(TEST_JPA_ECLIPSELINK_PROVIDER);

                if (enableEclipseLinkProvider != null && Boolean.valueOf(enableEclipseLinkProvider)) {
                    providers.add(new org.eclipse.persistence.jpa.PersistenceProvider());
                } else {
                    providers.add(new HibernatePersistenceProvider());
                }

                return providers;
            }

            @Override
            public void clearCachedProviders() {
            }
        });
    }

    public static EntityManagerFactory createEntityManagerFactory(String unitName) {
        return Persistence.createEntityManagerFactory(unitName);
    }

}
