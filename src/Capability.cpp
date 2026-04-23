/*
 * HXTP Embedded SDK v1.0.3
 * Capability Registry — Implementation
 *
 * Fixed-array capability storage. No heap allocation.
 * Unknown actions are rejected (fail-closed).
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#include "Capability.h"
#include <cstring>

namespace hxtp {

CapabilityRegistry::CapabilityRegistry() : count_(0) {
    memset(entries_, 0, sizeof(entries_));
}

bool CapabilityRegistry::register_capability(
    uint16_t id,
    const char* action,
    CapabilityHandler handler,
    void* user_ctx)
{
    if (!action || !handler) return false;
    if (count_ >= MaxCapabilities) return false;

    /* Check for duplicate ID or action */
    for (size_t i = 0; i < count_; ++i) {
        if (entries_[i].active) {
            if (entries_[i].id == id) return false;
            if (strcmp(entries_[i].action, action) == 0) return false;
        }
    }

    CapabilityEntry& e = entries_[count_];
    e.id = id;

    size_t alen = strlen(action);
    if (alen >= sizeof(e.action)) alen = sizeof(e.action) - 1;
    memcpy(e.action, action, alen);
    e.action[alen] = '\0';

    e.handler  = handler;
    e.user_ctx = user_ctx;
    e.active   = true;

    ++count_;
    return true;
}

Error CapabilityRegistry::lookup_by_action(
    const char* action,
    const CapabilityEntry** out_entry) const
{
    if (!action || !out_entry) return Error::INVALID_PARAMS;

    for (size_t i = 0; i < count_; ++i) {
        if (entries_[i].active && strcmp(entries_[i].action, action) == 0) {
            *out_entry = &entries_[i];
            return Error::OK;
        }
    }

    return Error::CAPABILITY_NOT_REGISTERED;
}

Error CapabilityRegistry::lookup_by_id(
    uint16_t id,
    const CapabilityEntry** out_entry) const
{
    if (!out_entry) return Error::INVALID_PARAMS;

    for (size_t i = 0; i < count_; ++i) {
        if (entries_[i].active && entries_[i].id == id) {
            *out_entry = &entries_[i];
            return Error::OK;
        }
    }

    return Error::CAPABILITY_NOT_REGISTERED;
}

CapabilityResult CapabilityRegistry::execute(
    const char* action,
    const char* params_json,
    uint32_t params_len) const
{
    CapabilityResult result;
    memset(&result, 0, sizeof(result));

    const CapabilityEntry* entry = nullptr;
    Error err = lookup_by_action(action, &entry);

    if (err != Error::OK || !entry || !entry->handler) {
        result.success    = false;
        result.error_code = static_cast<int16_t>(Error::CAPABILITY_NOT_REGISTERED);
        const char* msg   = "CAPABILITY_NOT_REGISTERED";
        size_t mlen = strlen(msg);
        if (mlen >= sizeof(result.error_msg)) mlen = sizeof(result.error_msg) - 1;
        memcpy(result.error_msg, msg, mlen);
        result.error_msg[mlen] = '\0';
        return result;
    }

    /* Execute handler */
    result = entry->handler(params_json, params_len, entry->user_ctx);
    return result;
}

} /* namespace hxtp */
