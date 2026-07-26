package io.github.hectorvent.floci.services.ec2.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public enum GuestCommandReadiness {
    PENDING,
    READY,
    UNAVAILABLE
}
