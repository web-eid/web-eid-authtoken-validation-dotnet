// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

export function parsePayload(context) {
    const fragment = window.location.hash.slice(1);

    if (!fragment) {
        throw new Error(`Missing ${context} response payload`);
    }

    let payload;
    try {
        payload = JSON.parse(atob(fragment));
    } catch (e) {
        console.error(e);
        throw new Error(`Failed to parse the ${context} response`);
    }

    if (payload.error) {
        const error = new Error(payload.message ?? `${context} failed`);
        error.code = payload.code;
        throw error;
    }

    return payload;
}
