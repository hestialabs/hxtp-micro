/*
 * HXTP Embedded SDK v1.0
 * Capability Registry — Header
 *
 * Fixed-array capability registry. No dynamic allocation.
 * Only registered capabilities may execute. Unknown actions are rejected.
 *
 * Platform-agnostic. NO Arduino includes.
 *
 * Copyright (c) 2026 Hestia Labs
 * SDK-License-Identifier: MIT
 */

#ifndef CAPABILITY_H
#define CAPABILITY_H

#include "Types.h"
#include "Errors.h"

namespace hxtp {

class CapabilityRegistry {
public:
    CapabilityRegistry();

    /**
     * Register a capability handler.
     * @param id       Unique capability ID
     * @param action   Action name string (e.g., "set_pin")
     * @param handler  Function pointer to execute
     * @param user_ctx Opaque user context passed to handler
     * @return         true on success, false if full or duplicate
     */
    bool register_capability(
        uint16_t id,
        const char* action,
        CapabilityHandler handler,
        void* user_ctx = nullptr
    );

    /**
     * Look up a capability by action name.
     * @param action     Action string from command
     * @param out_entry  Receives pointer to entry (if found)
     * @return           Error::OK if found, CAPABILITY_NOT_REGISTERED otherwise
     */
    Error lookup_by_action(const char* action, const CapabilityEntry** out_entry) const;

    /**
     * Look up a capability by ID.
     */
    Error lookup_by_id(uint16_t id, const CapabilityEntry** out_entry) const;

    /**
     * Execute a command. Looks up the capability and calls its handler.
     * @param action      Action string
     * @param params_json Raw params JSON
     * @param params_len  Length of params JSON
     * @return            CapabilityResult
     */
    CapabilityResult execute(
        const char* action,
        const char* params_json,
        uint32_t params_len
    ) const;

    size_t count() const { return count_; }

private:
    CapabilityEntry entries_[MaxCapabilities];
    size_t              count_;
};

} /* namespace hxtp */

#endif /* CAPABILITY_H */
