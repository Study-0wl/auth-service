package com.studyowl.authservice.dto;

// Mirrors user-profile-service's Role enum exactly (dto/Role.java) - same two
// values, same names - since this is serialized straight through to that
// service's ProfileRequest.role with no translation.
public enum Role {
    STUDENT, OWNER
}
