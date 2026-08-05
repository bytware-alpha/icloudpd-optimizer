#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* This translation unit has no networking or optimizer dependencies. */
enum { KC_AUTHORIZED = 0, KC_NOT_FOUND = 1, KC_AMBIGUOUS = 2,
       KC_INTERACTION = 3, KC_DENIED = 4, KC_INTEGRITY = 5 };

/* The C boundary returns only these fixed diagnostic codes for store/prove
 * failures. Rust rejects every other value. No OSStatus, item metadata,
 * requirement text, path, or Security.framework error crosses this boundary. */
enum {
  KC_KEYCHAIN_DIAGNOSTIC_BASE = 1000,
  KC_KEYCHAIN_DIAGNOSTIC_REASON_STRIDE = 8,
  KC_KEYCHAIN_STAGE_HELPER_REQUIREMENT = 1,
  KC_KEYCHAIN_STAGE_DURABLE_ACCESS_CONSTRUCTION = 2,
  KC_KEYCHAIN_STAGE_V2_ENUMERATION = 3,
  KC_KEYCHAIN_STAGE_ITEM_CREATION = 4,
  KC_KEYCHAIN_STAGE_REENUMERATION_IDENTITY = 5,
  KC_KEYCHAIN_STAGE_GENERATED_ACL_PROOF = 6,
  KC_KEYCHAIN_STAGE_NO_UI_DATA_PROOF = 7,
  KC_KEYCHAIN_STAGE_DATA_ONLY_REPLACEMENT = 8,
  KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF = 9,
  KC_KEYCHAIN_STAGE_ROLLBACK = 10,
  KC_KEYCHAIN_REASON_INTEGRITY_MISMATCH = 1,
  KC_KEYCHAIN_REASON_INTERACTION_REQUIRED = 2,
  KC_KEYCHAIN_REASON_ACCESS_DENIED = 3,
  KC_KEYCHAIN_REASON_AMBIGUOUS = 4,
  KC_KEYCHAIN_REASON_NOT_FOUND = 5,
};

/* Runtime access is intentionally namespace-rotated.  The v1 value is kept
 * only as an inert label for a later, separately authorized inventory/cleanup
 * operation; no query, read, update, or deletion path may reference it. */
static const char optimizer_domain_v1_retired[] __attribute__((unused)) =
    "com.icloudpd-optimizer.smb.v1";
static const char optimizer_domain_v2[] = "com.icloudpd-optimizer.smb.v2";
static const char requirement_prefix[] = "designated => ";
static const char helper_requirement_description[] =
    "csreq://com.icloudpd-optimizer.helper";
static pthread_mutex_t keychain_interaction_lock = PTHREAD_MUTEX_INITIALIZER;

/* These narrowly-scoped Security.framework interfaces are exported on macOS,
 * but are not in the public SDK header. They are the only supported legacy ACL
 * representation that records an explicit code requirement instead of a path
 * snapshot. If an OS removes either symbol, fail closed rather than fall back
 * to a path/hash ACL whose update semantics are ambiguous. */
extern OSStatus SecTrustedApplicationCreateFromRequirement(
    const char *description, SecRequirementRef requirement,
    SecTrustedApplicationRef *app) __attribute__((weak_import));
extern OSStatus SecTrustedApplicationCopyExternalRepresentation(
    SecTrustedApplicationRef app, CFDataRef *external)
    __attribute__((weak_import));

static int map_status(OSStatus status) {
  if (status == errSecSuccess) return KC_AUTHORIZED;
  if (status == errSecItemNotFound) return KC_NOT_FOUND;
  if (status == errSecInteractionNotAllowed) return KC_INTERACTION;
  if (status == errSecAuthFailed || status == errSecUserCanceled) return KC_DENIED;
  return KC_INTEGRITY;
}

static int keychain_diagnostic(int stage, int result) {
  int reason = KC_KEYCHAIN_REASON_INTEGRITY_MISMATCH;
  if (stage < KC_KEYCHAIN_STAGE_HELPER_REQUIREMENT ||
      stage > KC_KEYCHAIN_STAGE_ROLLBACK) return KC_INTEGRITY;
  switch (result) {
    case KC_NOT_FOUND:
      reason = KC_KEYCHAIN_REASON_NOT_FOUND;
      break;
    case KC_AMBIGUOUS:
      reason = KC_KEYCHAIN_REASON_AMBIGUOUS;
      break;
    case KC_INTERACTION:
      reason = KC_KEYCHAIN_REASON_INTERACTION_REQUIRED;
      break;
    case KC_DENIED:
      reason = KC_KEYCHAIN_REASON_ACCESS_DENIED;
      break;
    default:
      break;
  }
  return KC_KEYCHAIN_DIAGNOSTIC_BASE +
      stage * KC_KEYCHAIN_DIAGNOSTIC_REASON_STRIDE + reason;
}

static Boolean requirement_expression(const char *canonical, const char **out) {
  if (!canonical || !out ||
      strncmp(canonical, requirement_prefix, sizeof(requirement_prefix) - 1) != 0 ||
      canonical[sizeof(requirement_prefix) - 1] == '\0') return false;
  *out = canonical + sizeof(requirement_prefix) - 1;
  return true;
}

static Boolean trusted_application_equal(SecTrustedApplicationRef left,
                                         SecTrustedApplicationRef right) {
  if (!left || !right || !SecTrustedApplicationCopyExternalRepresentation) return false;
  CFDataRef left_data = NULL, right_data = NULL;
  OSStatus left_status = SecTrustedApplicationCopyExternalRepresentation(left, &left_data);
  OSStatus right_status = SecTrustedApplicationCopyExternalRepresentation(right, &right_data);
  Boolean equal = left_status == errSecSuccess && right_status == errSecSuccess &&
      left_data != NULL && right_data != NULL && CFEqual(left_data, right_data);
  if (left_data) CFRelease(left_data);
  if (right_data) CFRelease(right_data);
  return equal;
}

typedef Boolean (*array_element_equal)(const void *left, const void *right);

static Boolean trusted_application_element_equal(const void *left, const void *right) {
  return trusted_application_equal((SecTrustedApplicationRef)left,
                                   (SecTrustedApplicationRef)right);
}

static Boolean cf_element_equal(const void *left, const void *right) {
  return CFEqual(left, right);
}

/* Security.framework is free to order set-like ACL members differently after
 * serialization. Match as a multiset so reordering is not mistaken for a
 * migration, while still rejecting every extra, missing, or duplicate member. */
static int arrays_equal_as_multiset(CFArrayRef left, CFArrayRef right,
                                    array_element_equal element_equal,
                                    Boolean *equal) {
  if (!element_equal || !equal) return KC_INTEGRITY;
  *equal = false;
  if (!left || !right) {
    *equal = left == right;
    return KC_AUTHORIZED;
  }
  CFIndex count = CFArrayGetCount(left);
  if (count != CFArrayGetCount(right)) return KC_AUTHORIZED;
  if (count == 0) {
    *equal = true;
    return KC_AUTHORIZED;
  }
  if (count < 0 || (uintmax_t)count > SIZE_MAX / sizeof(Boolean)) {
    return KC_INTEGRITY;
  }
  Boolean *matched = calloc((size_t)count, sizeof(*matched));
  if (!matched) return KC_INTEGRITY;
  for (CFIndex i = 0; i < count; ++i) {
    Boolean found = false;
    const void *left_value = CFArrayGetValueAtIndex(left, i);
    for (CFIndex j = 0; j < count; ++j) {
      if (!matched[j] && element_equal(left_value, CFArrayGetValueAtIndex(right, j))) {
        matched[j] = true;
        found = true;
        break;
      }
    }
    if (!found) {
      free(matched);
      return KC_AUTHORIZED;
    }
  }
  free(matched);
  *equal = true;
  return KC_AUTHORIZED;
}

static int application_arrays_equal(CFArrayRef left, CFArrayRef right,
                                    Boolean *equal) {
  return arrays_equal_as_multiset(left, right, trusted_application_element_equal, equal);
}

static int authorization_arrays_equal(CFArrayRef left, CFArrayRef right,
                                      Boolean *equal) {
  return arrays_equal_as_multiset(left, right, cf_element_equal, equal);
}

static Boolean nullable_strings_equal(CFStringRef left, CFStringRef right) {
  if (!left || !right) return left == right;
  return CFEqual(left, right);
}

static int acl_equal(SecACLRef left, SecACLRef right, Boolean *equal) {
  CFArrayRef left_apps = NULL, right_apps = NULL, left_authorizations = NULL,
      right_authorizations = NULL;
  CFStringRef left_description = NULL, right_description = NULL;
  SecKeychainPromptSelector left_prompt = 0, right_prompt = 0;
  Boolean applications_equal = false, authorizations_equal = false;
  int result = KC_AUTHORIZED;
  if (!left || !right || !equal) return KC_INTEGRITY;
  *equal = false;
  OSStatus status = SecACLCopyContents(left, &left_apps, &left_description, &left_prompt);
  if (status != errSecSuccess) goto fail;
  status = SecACLCopyContents(right, &right_apps, &right_description, &right_prompt);
  if (status != errSecSuccess) goto fail;
  left_authorizations = SecACLCopyAuthorizations(left);
  right_authorizations = SecACLCopyAuthorizations(right);
  if (!left_authorizations || !right_authorizations) goto fail;
  result = application_arrays_equal(left_apps, right_apps, &applications_equal);
  if (result != KC_AUTHORIZED) goto fail;
  result = authorization_arrays_equal(left_authorizations, right_authorizations,
                                      &authorizations_equal);
  if (result != KC_AUTHORIZED) goto fail;
  *equal = left_prompt == right_prompt &&
      nullable_strings_equal(left_description, right_description) &&
      applications_equal && authorizations_equal;
  if (left_apps) CFRelease(left_apps);
  if (right_apps) CFRelease(right_apps);
  if (left_description) CFRelease(left_description);
  if (right_description) CFRelease(right_description);
  CFRelease(left_authorizations); CFRelease(right_authorizations);
  return KC_AUTHORIZED;
fail:
  if (left_apps) CFRelease(left_apps); if (right_apps) CFRelease(right_apps);
  if (left_description) CFRelease(left_description);
  if (right_description) CFRelease(right_description);
  if (left_authorizations) CFRelease(left_authorizations);
  if (right_authorizations) CFRelease(right_authorizations);
  return result != KC_AUTHORIZED ? result :
      (status == errSecSuccess ? KC_INTEGRITY : map_status(status));
}

static int access_copy_owner_and_acls(SecAccessRef access, uid_t *user_id,
                                      gid_t *group_id, SecAccessOwnerType *owner_type,
                                      CFArrayRef *acls) {
  if (!access || !user_id || !group_id || !owner_type || !acls) return KC_INTEGRITY;
  *acls = NULL;
  /* On current macOS, SecAccessCopyOwnerAndACL's legacy ACL output is not a
   * CFArray of SecACL objects (its elements have a different CFTypeID).  It
   * is still the supported owner accessor, so request only the owner fields
   * and obtain the typed ACL list through SecAccessCopyACLList.  Treat either
   * operation's failure as a closed integrity gate. */
  OSStatus status = SecAccessCopyOwnerAndACL(access, user_id, group_id, owner_type, NULL);
  if (status != errSecSuccess) {
    return map_status(status);
  }
  status = SecAccessCopyACLList(access, acls);
  if (status != errSecSuccess) {
    if (*acls) { CFRelease(*acls); *acls = NULL; }
    return map_status(status);
  }
  if (!*acls || CFArrayGetCount(*acls) == 0) {
    if (*acls) { CFRelease(*acls); *acls = NULL; }
    return KC_INTEGRITY;
  }
  return KC_AUTHORIZED;
}

/* The keychain daemon adds two ACLs while persisting a SecAccess.  They are
 * not present in the newly-created SecAccess returned by SecAccessCreate:
 * the integrity ACL carries an item-specific digest, and the partition ACL
 * carries a hex-encoded XML property list binding the item to this signing
 * team's partition.  Neither field can be compared to the in-memory access
 * byte-for-byte, but both have a canonical persisted representation that is
 * validated here. */
static int acl_has_single_authorization(SecACLRef acl, CFStringRef authorization,
                                        Boolean *matches) {
  if (!acl || !authorization || !matches) return KC_INTEGRITY;
  *matches = false;
  CFArrayRef authorizations = SecACLCopyAuthorizations(acl);
  if (!authorizations) return KC_INTEGRITY;
  if (CFArrayGetCount(authorizations) == 1 &&
      CFEqual(CFArrayGetValueAtIndex(authorizations, 0), authorization)) {
    *matches = true;
  }
  CFRelease(authorizations);
  return KC_AUTHORIZED;
}

/* The digest text is item-specific and therefore cannot be compared against
 * the pre-persistence SecAccess.  Its binding is still exercised by the
 * interaction-free SecKeychainItemCopyAttributesAndData call in
 * prove_item_access_and_data_without_ui; securityd rejects a bad digest there.
 */
static int canonical_integrity_acl(SecACLRef acl, Boolean *matches) {
  if (!acl || !matches) return KC_INTEGRITY;
  *matches = false;
  int result = acl_has_single_authorization(acl, kSecACLAuthorizationIntegrity, matches);
  if (result != KC_AUTHORIZED || !*matches) return result;

  CFArrayRef applications = NULL;
  CFStringRef description = NULL;
  SecKeychainPromptSelector prompt = 0;
  OSStatus status = SecACLCopyContents(acl, &applications, &description, &prompt);
  if (status != errSecSuccess) return map_status(status);
  Boolean valid = applications == NULL && description != NULL &&
      CFGetTypeID(description) == CFStringGetTypeID() && prompt == 0;
  if (valid) {
    CFIndex length = CFStringGetLength(description);
    valid = length == 64;
    for (CFIndex index = 0; valid && index < length; ++index) {
      UniChar character = CFStringGetCharacterAtIndex(description, index);
      valid = (character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f');
    }
  }
  if (description) CFRelease(description);
  if (applications) CFRelease(applications);
  *matches = valid;
  return KC_AUTHORIZED;
}

static int copy_current_team_identifier(CFStringRef *team_identifier) {
  if (!team_identifier) return KC_INTEGRITY;
  *team_identifier = NULL;
  SecCodeRef current = NULL;
  SecStaticCodeRef static_code = NULL;
  CFDictionaryRef signing_information = NULL;
  OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &current);
  if (status == errSecSuccess && current) {
    status = SecCodeCopyStaticCode(current, kSecCSDefaultFlags, &static_code);
  }
  if (status == errSecSuccess && static_code) {
    status = SecCodeCopySigningInformation(static_code, kSecCSSigningInformation,
                                            &signing_information);
  }
  CFTypeRef value = signing_information
      ? CFDictionaryGetValue(signing_information, kSecCodeInfoTeamIdentifier)
      : NULL;
  if (status == errSecSuccess && value && CFGetTypeID(value) == CFStringGetTypeID()) {
    *team_identifier = (CFStringRef)CFRetain(value);
  }
  if (signing_information) CFRelease(signing_information);
  if (static_code) CFRelease(static_code);
  if (current) CFRelease(current);
  return *team_identifier ? KC_AUTHORIZED : KC_INTEGRITY;
}

static int canonical_partition_acl(SecACLRef acl, CFStringRef team_identifier,
                                   Boolean *matches) {
  if (!acl || !team_identifier || !matches) return KC_INTEGRITY;
  *matches = false;
  int result = acl_has_single_authorization(acl, kSecACLAuthorizationPartitionID, matches);
  if (result != KC_AUTHORIZED || !*matches) return result;

  CFArrayRef applications = NULL;
  CFStringRef description = NULL;
  SecKeychainPromptSelector prompt = 0;
  OSStatus status = SecACLCopyContents(acl, &applications, &description, &prompt);
  if (status != errSecSuccess) return map_status(status);
  Boolean valid = applications == NULL && description != NULL &&
      CFGetTypeID(description) == CFStringGetTypeID() && prompt == 0;
  CFDataRef encoded = NULL;
  CFPropertyListRef property_list = NULL;
  CFErrorRef error = NULL;
  CFStringRef expected_partition = NULL;
  if (valid) {
    CFIndex character_count = CFStringGetLength(description);
    /* securityd stores the partition plist as lowercase hexadecimal text.
     * Decode that canonical transport form before comparing its semantics. */
    valid = character_count > 0 && (character_count % 2) == 0 &&
        (uintmax_t)character_count <= SIZE_MAX / 2;
    if (valid) {
      size_t byte_count = (size_t)character_count / 2;
      UInt8 *bytes = malloc(byte_count);
      if (!bytes) {
        valid = false;
      } else {
        for (CFIndex index = 0; valid && index < character_count; index += 2) {
          UniChar high = CFStringGetCharacterAtIndex(description, index);
          UniChar low = CFStringGetCharacterAtIndex(description, index + 1);
          int high_value = high >= '0' && high <= '9' ? (int)(high - '0') :
              high >= 'a' && high <= 'f' ? (int)(high - 'a' + 10) :
              high >= 'A' && high <= 'F' ? (int)(high - 'A' + 10) : -1;
          int low_value = low >= '0' && low <= '9' ? (int)(low - '0') :
              low >= 'a' && low <= 'f' ? (int)(low - 'a' + 10) :
              low >= 'A' && low <= 'F' ? (int)(low - 'A' + 10) : -1;
          if (high_value < 0 || low_value < 0) {
            valid = false;
          } else {
            bytes[index / 2] = (UInt8)((high_value << 4) | low_value);
          }
        }
        if (valid) encoded = CFDataCreate(kCFAllocatorDefault, bytes, (CFIndex)byte_count);
        free(bytes);
        valid = valid && encoded != NULL;
      }
    }
  }
  if (valid) {
    property_list = CFPropertyListCreateWithData(kCFAllocatorDefault, encoded,
                                                  kCFPropertyListImmutable, NULL, &error);
    valid = property_list != NULL &&
        CFGetTypeID(property_list) == CFDictionaryGetTypeID();
  }
  CFArrayRef partitions = NULL;
  if (valid) {
    CFDictionaryRef dictionary = (CFDictionaryRef)property_list;
    CFTypeRef value = CFDictionaryGetValue(dictionary, CFSTR("Partitions"));
    partitions = (CFArrayRef)value;
    valid = CFDictionaryGetCount(dictionary) == 1 && partitions != NULL &&
        CFGetTypeID(partitions) == CFArrayGetTypeID() &&
        CFArrayGetCount(partitions) == 1;
  }
  if (valid) {
    expected_partition = CFStringCreateWithFormat(kCFAllocatorDefault, NULL,
                                                  CFSTR("teamid:%@"), team_identifier);
    CFTypeRef partition = CFArrayGetValueAtIndex(partitions, 0);
    valid = expected_partition != NULL && partition != NULL &&
        CFGetTypeID(partition) == CFStringGetTypeID() &&
        CFEqual(partition, expected_partition);
  }
  if (expected_partition) CFRelease(expected_partition);
  if (property_list) CFRelease(property_list);
  if (error) CFRelease(error);
  if (encoded) CFRelease(encoded);
  if (description) CFRelease(description);
  if (applications) CFRelease(applications);
  *matches = valid;
  return KC_AUTHORIZED;
}

static int persisted_acl_multisets_equal(CFArrayRef actual_acls,
                                          CFArrayRef expected_acls,
                                          CFStringRef team_identifier,
                                          Boolean *matches) {
  if (!actual_acls || !expected_acls || !team_identifier || !matches) return KC_INTEGRITY;
  *matches = false;
  CFIndex actual_count = CFArrayGetCount(actual_acls);
  CFIndex expected_count = CFArrayGetCount(expected_acls);
  if (actual_count < 0 || expected_count < 0 || actual_count < expected_count ||
      actual_count - expected_count != 2 ||
      (uintmax_t)expected_count > SIZE_MAX / sizeof(Boolean)) {
    return KC_AUTHORIZED;
  }
  Boolean *expected_matched = calloc((size_t)expected_count, sizeof(*expected_matched));
  if (!expected_matched) return KC_INTEGRITY;
  Boolean integrity_seen = false, partition_seen = false;
  for (CFIndex actual_index = 0; actual_index < actual_count; ++actual_index) {
    SecACLRef actual = (SecACLRef)CFArrayGetValueAtIndex(actual_acls, actual_index);
    Boolean found = false;
    for (CFIndex expected_index = 0; expected_index < expected_count; ++expected_index) {
      if (expected_matched[expected_index]) continue;
      Boolean same = false;
      int result = acl_equal(actual,
          (SecACLRef)CFArrayGetValueAtIndex(expected_acls, expected_index), &same);
      if (result != KC_AUTHORIZED) {
        free(expected_matched);
        return result;
      }
      if (same) {
        expected_matched[expected_index] = true;
        found = true;
        break;
      }
    }
    if (found) continue;
    Boolean system_match = false;
    int result = canonical_integrity_acl(actual, &system_match);
    if (result != KC_AUTHORIZED) {
      free(expected_matched);
      return result;
    }
    if (system_match) {
      if (integrity_seen) {
        free(expected_matched);
        return KC_AUTHORIZED;
      }
      integrity_seen = true;
      continue;
    }
    result = canonical_partition_acl(actual, team_identifier, &system_match);
    if (result != KC_AUTHORIZED) {
      free(expected_matched);
      return result;
    }
    if (!system_match || partition_seen) {
      free(expected_matched);
      return KC_AUTHORIZED;
    }
    partition_seen = true;
  }
  Boolean all_expected = true;
  for (CFIndex index = 0; index < expected_count; ++index) {
    if (!expected_matched[index]) {
      all_expected = false;
      break;
    }
  }
  free(expected_matched);
  *matches = all_expected && integrity_seen && partition_seen;
  return KC_AUTHORIZED;
}

/* Compare generated ownership and the complete ACL multiset, not merely a
 * path string or one decrypt entry. This prevents a freshly-created same-
 * tuple record with an added reader, broad owner, or reordered duplicate ACL
 * from being accepted as the durable v2 credential. */
static int access_matches_generated_shape(SecAccessRef actual, SecAccessRef expected,
                                          Boolean *matches) {
  uid_t actual_user = 0, expected_user = 0;
  gid_t actual_group = 0, expected_group = 0;
  SecAccessOwnerType actual_owner_type = 0, expected_owner_type = 0;
  CFArrayRef actual_acls = NULL, expected_acls = NULL;
  if (!actual || !expected || !matches) return KC_INTEGRITY;
  *matches = false;
  int result = access_copy_owner_and_acls(actual, &actual_user, &actual_group,
                                          &actual_owner_type, &actual_acls);
  if (result != KC_AUTHORIZED) goto done;
  result = access_copy_owner_and_acls(expected, &expected_user, &expected_group,
                                      &expected_owner_type, &expected_acls);
  if (result != KC_AUTHORIZED) goto done;
  if (actual_user != expected_user || actual_group != expected_group ||
      actual_owner_type != expected_owner_type) goto done;
  CFIndex actual_count = CFArrayGetCount(actual_acls);
  CFIndex expected_count = CFArrayGetCount(expected_acls);
  if (actual_count < 0 || expected_count < 0 || actual_count < expected_count ||
      actual_count - expected_count != 2) goto done;
  CFStringRef team_identifier = NULL;
  result = copy_current_team_identifier(&team_identifier);
  if (result == KC_AUTHORIZED) {
    result = persisted_acl_multisets_equal(actual_acls, expected_acls,
                                            team_identifier, matches);
  }
  if (team_identifier) CFRelease(team_identifier);
done:
  if (actual_acls) CFRelease(actual_acls);
  if (expected_acls) CFRelease(expected_acls);
  return result;
}

static int item_access_matches(SecKeychainItemRef item, SecAccessRef expected,
                               Boolean *matches) {
  SecAccessRef actual = NULL;
  if (!item || !expected || !matches) return KC_INTEGRITY;
  *matches = false;
  OSStatus status = SecKeychainItemCopyAccess(item, &actual);
  if (status != errSecSuccess) return map_status(status);
  if (!actual) return KC_INTEGRITY;
  int result = access_matches_generated_shape(actual, expected, matches);
  CFRelease(actual);
  return result;
}

static int create_requirement(const char *canonical_requirement,
                              SecRequirementRef *out) {
  const char *expression = NULL; CFStringRef requirement_string = NULL;
  if (!out) return KC_INTEGRITY;
  *out = NULL;
  if (!requirement_expression(canonical_requirement, &expression)) return KC_INTEGRITY;
  requirement_string = CFStringCreateWithCString(kCFAllocatorDefault, expression,
                                                   kCFStringEncodingUTF8);
  if (!requirement_string) return KC_INTEGRITY;
  OSStatus status = SecRequirementCreateWithString(requirement_string, kSecCSDefaultFlags, out);
  CFRelease(requirement_string);
  if (status != errSecSuccess) return map_status(status);
  return *out ? KC_AUTHORIZED : KC_INTEGRITY;
}

static int create_requirement_bound_helper(const char *canonical_requirement,
                                           SecTrustedApplicationRef *out) {
  if (!out || !SecTrustedApplicationCreateFromRequirement) return KC_INTEGRITY;
  *out = NULL;
  SecRequirementRef requirement = NULL;
  int result = create_requirement(canonical_requirement, &requirement);
  if (result != KC_AUTHORIZED) return result;
  OSStatus status = SecTrustedApplicationCreateFromRequirement(helper_requirement_description,
                                                               requirement, out);
  CFRelease(requirement);
  if (status != errSecSuccess) return map_status(status);
  return *out ? KC_AUTHORIZED : KC_INTEGRITY;
}

static int current_helper_matches_requirement(const char *canonical_requirement) {
  SecRequirementRef requirement = NULL; SecCodeRef current = NULL;
  int result = create_requirement(canonical_requirement, &requirement);
  if (result != KC_AUTHORIZED) return result;
  OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &current);
  if (status == errSecSuccess && current) {
    /* Match the exact dynamic-code check securityd applies to a requirement ACL. */
    status = SecCodeCheckValidity(current, kSecCSDefaultFlags, requirement);
  }
  if (current) CFRelease(current);
  if (requirement) CFRelease(requirement);
  return status == errSecSuccess ? KC_AUTHORIZED : KC_INTEGRITY;
}

static int create_access(SecTrustedApplicationRef helper, SecAccessRef *out) {
  if (!helper || !out) return KC_INTEGRITY;
  *out = NULL;
  const void *one_helper[] = { helper };
  CFArrayRef applications = CFArrayCreate(kCFAllocatorDefault, one_helper, 1,
                                          &kCFTypeArrayCallBacks);
  if (!applications) return KC_INTEGRITY;
  OSStatus status = SecAccessCreate(CFSTR("iCloudPD Optimizer SMB credential"),
                                    applications, out);
  CFRelease(applications);
  if (status != errSecSuccess) return map_status(status);
  return *out ? KC_AUTHORIZED : KC_INTEGRITY;
}

/* Search may initially include differing domain/path records; filter every
 * metadata-only result and require exactly one complete v2 tuple.  The
 * retired v1 namespace is intentionally absent from both the search and the
 * post-search comparison. */
static int exact_v2_item(const char *server, const char *account, SecKeychainItemRef *out) {
  if (!server || !account || !out) return KC_INTEGRITY;
  *out = NULL;
  SecKeychainAttribute attrs[6];
  UInt32 protocol = kSecProtocolTypeSMB, authentication_type = kSecAuthenticationTypeDefault, zero = 0;
  attrs[0] = (SecKeychainAttribute){ kSecServerItemAttr, (UInt32)strlen(server), (void *)server };
  attrs[1] = (SecKeychainAttribute){ kSecAccountItemAttr, (UInt32)strlen(account), (void *)account };
  attrs[2] = (SecKeychainAttribute){ kSecSecurityDomainItemAttr, sizeof(optimizer_domain_v2) - 1, (void *)optimizer_domain_v2 };
  attrs[3] = (SecKeychainAttribute){ kSecProtocolItemAttr, sizeof(protocol), &protocol };
  attrs[4] = (SecKeychainAttribute){ kSecPortItemAttr, sizeof(zero), &zero };
  attrs[5] = (SecKeychainAttribute){ kSecAuthenticationTypeItemAttr, sizeof(authentication_type), &authentication_type };
  SecKeychainAttributeList query = { 6, attrs };
  SecKeychainSearchRef search = NULL;
  OSStatus status = SecKeychainSearchCreateFromAttributes(NULL, kSecInternetPasswordItemClass, &query, &search);
  if (status != errSecSuccess) return map_status(status);
  if (!search) return KC_INTEGRITY;
  UInt32 tags[] = { kSecServerItemAttr, kSecAccountItemAttr, kSecProtocolItemAttr,
                    kSecPortItemAttr, kSecAuthenticationTypeItemAttr,
                    kSecSecurityDomainItemAttr, kSecPathItemAttr };
  SecKeychainAttributeInfo info = { 7, tags, NULL };
  SecKeychainItemRef match = NULL;
  for (;;) {
    SecKeychainItemRef candidate = NULL;
    status = SecKeychainSearchCopyNext(search, &candidate);
    if (status == errSecItemNotFound) break;
    if (status != errSecSuccess) { if (match) CFRelease(match); CFRelease(search); return map_status(status); }
    if (!candidate) { if (match) CFRelease(match); CFRelease(search); return KC_INTEGRITY; }
    SecKeychainAttributeList *found = NULL;
    status = SecKeychainItemCopyAttributesAndData(candidate, &info, NULL, &found, NULL, NULL);
    if (status != errSecSuccess || !found) {
      CFRelease(candidate); if (match) CFRelease(match); CFRelease(search);
      return status == errSecSuccess ? KC_INTEGRITY : map_status(status);
    }
    Boolean exact = found->count == 7 && found->attr != NULL &&
        found->attr[0].length == strlen(server) &&
        memcmp(found->attr[0].data, server, found->attr[0].length) == 0 &&
        found->attr[1].length == strlen(account) &&
        memcmp(found->attr[1].data, account, found->attr[1].length) == 0 &&
        found->attr[2].length == sizeof(protocol) && memcmp(found->attr[2].data, &protocol, sizeof(protocol)) == 0 &&
        found->attr[3].length == sizeof(zero) && memcmp(found->attr[3].data, &zero, sizeof(zero)) == 0 &&
        found->attr[4].length == sizeof(authentication_type) &&
        memcmp(found->attr[4].data, &authentication_type, sizeof(authentication_type)) == 0 &&
        found->attr[5].length == sizeof(optimizer_domain_v2) - 1 && memcmp(found->attr[5].data, optimizer_domain_v2, sizeof(optimizer_domain_v2) - 1) == 0 &&
        found->attr[6].length == 0;
    SecKeychainItemFreeAttributesAndData(found, NULL);
    if (!exact) { CFRelease(candidate); continue; }
    if (match) { CFRelease(candidate); CFRelease(match); CFRelease(search); return KC_AMBIGUOUS; }
    match = candidate;
  }
  CFRelease(search);
  if (!match) return KC_NOT_FOUND;
  *out = match;
  return KC_AUTHORIZED;
}

static int begin_without_interaction(Boolean *original_allowed) {
  if (!original_allowed) return KC_INTEGRITY;
  if (pthread_mutex_lock(&keychain_interaction_lock) != 0) return KC_INTEGRITY;
  OSStatus status = SecKeychainGetUserInteractionAllowed(original_allowed);
  if (status != errSecSuccess) {
    pthread_mutex_unlock(&keychain_interaction_lock);
    return map_status(status);
  }
  status = SecKeychainSetUserInteractionAllowed(false);
  if (status != errSecSuccess) {
    SecKeychainSetUserInteractionAllowed(*original_allowed);
    pthread_mutex_unlock(&keychain_interaction_lock);
    return map_status(status);
  }
  return KC_AUTHORIZED;
}

static int finish_without_interaction(Boolean original_allowed, int result) {
  OSStatus restore = SecKeychainSetUserInteractionAllowed(original_allowed);
  int unlock = pthread_mutex_unlock(&keychain_interaction_lock);
  return restore == errSecSuccess && unlock == 0 ? result : KC_INTEGRITY;
}

/* A restore failure is itself part of the no-UI proof boundary. Preserve an
 * earlier fixed diagnostic only when restoration succeeded; otherwise report
 * the restore as an integrity mismatch at the supplied fixed stage. */
static int finish_without_interaction_with_diagnostic(Boolean original_allowed,
                                                      int result, int stage) {
  int finished = finish_without_interaction(original_allowed, result);
  return finished == result ? result : keychain_diagnostic(stage, finished);
}

static void zeroize_and_free_data(UInt32 length, void *data) {
  if (!data) return;
  if (length) memset(data, 0, length);
  SecKeychainItemFreeAttributesAndData(NULL, data);
}

/* Callers hold keychain_interaction_lock from begin_without_interaction through
 * finish_without_interaction, including metadata enumeration and this read. */
static int copy_data_with_interaction_disabled(SecKeychainItemRef item, UInt32 *length,
                                               void **data) {
  if (!item || !length || !data) return KC_INTEGRITY;
  *length = 0; *data = NULL;
  OSStatus status = SecKeychainItemCopyAttributesAndData(item, NULL, NULL, NULL, length, data);
  int result = status == errSecSuccess ? KC_AUTHORIZED : map_status(status);
  if (result != KC_AUTHORIZED) {
    zeroize_and_free_data(*length, *data);
    *data = NULL; *length = 0;
  }
  return result;
}

int keychain_prove_exact_smb_credential(const char *server, const char *account,
                                        const char *helper_requirement) {
  int result = current_helper_matches_requirement(helper_requirement);
  if (result != KC_AUTHORIZED) {
    return keychain_diagnostic(KC_KEYCHAIN_STAGE_HELPER_REQUIREMENT, result);
  }
  Boolean original_allowed = false;
  result = begin_without_interaction(&original_allowed);
  if (result != KC_AUTHORIZED) {
    return keychain_diagnostic(KC_KEYCHAIN_STAGE_NO_UI_DATA_PROOF, result);
  }
  SecKeychainItemRef item = NULL;
  result = exact_v2_item(server, account, &item);
  if (result != KC_AUTHORIZED) {
    result = keychain_diagnostic(KC_KEYCHAIN_STAGE_V2_ENUMERATION, result);
  }
  if (result == KC_AUTHORIZED) {
    UInt32 length = 0; void *data = NULL;
    result = copy_data_with_interaction_disabled(item, &length, &data);
    zeroize_and_free_data(length, data);
    if (result == KC_AUTHORIZED && !length) result = KC_INTEGRITY;
    if (result != KC_AUTHORIZED) {
      result = keychain_diagnostic(KC_KEYCHAIN_STAGE_NO_UI_DATA_PROOF, result);
    }
  }
  if (item) CFRelease(item);
  return finish_without_interaction_with_diagnostic(
      original_allowed, result, KC_KEYCHAIN_STAGE_NO_UI_DATA_PROOF);
}

/* Production and recovery use this same exact-item enumerator. It returns the
 * Security.framework allocation and item only after the complete dedicated
 * tuple has exactly one match; the Rust caller zeroes and releases the data. */
int keychain_copy_exact_smb_credential(const char *server, const char *account,
                                       UInt32 *length, void **data,
                                       SecKeychainItemRef *item) {
  if (!length || !data || !item) return KC_INTEGRITY;
  *length = 0; *data = NULL; *item = NULL;
  Boolean original_allowed = false;
  int result = begin_without_interaction(&original_allowed);
  if (result != KC_AUTHORIZED) return result;
  result = exact_v2_item(server, account, item);
  if (result == KC_AUTHORIZED) {
    result = copy_data_with_interaction_disabled(*item, length, data);
  }
  result = finish_without_interaction(original_allowed, result);
  if (result != KC_AUTHORIZED || !*data || !*length) {
    zeroize_and_free_data(*length, *data);
    *data = NULL; *length = 0;
    if (*item) { CFRelease(*item); *item = NULL; }
    if (result == KC_AUTHORIZED) result = KC_INTEGRITY;
  }
  return result;
}

/* The store path is explicitly dashboard-mediated. Keep no-UI scopes above
 * limited to proof/recovery so authorized setup can request the one required
 * ownership change while still refusing a post-write interactive read. */

void keychain_zeroize_and_free_exact_smb_credential(UInt32 length, void *data) {
  zeroize_and_free_data(length, data);
}

static int create_exact_v2_item(const char *server, const char *account,
                                const unsigned char *password, size_t password_length,
                                SecAccessRef access, SecKeychainItemRef *item) {
  if (!server || !account || !password || !password_length || !access || !item) {
    return KC_INTEGRITY;
  }
  *item = NULL;
  UInt32 protocol = kSecProtocolTypeSMB, authentication_type = kSecAuthenticationTypeDefault,
         zero = 0;
  SecKeychainAttribute attrs[7] = {
      { kSecServerItemAttr, (UInt32)strlen(server), (void *)server },
      { kSecSecurityDomainItemAttr, sizeof(optimizer_domain_v2) - 1, (void *)optimizer_domain_v2 },
      { kSecAccountItemAttr, (UInt32)strlen(account), (void *)account },
      { kSecPathItemAttr, 0, NULL },
      { kSecPortItemAttr, sizeof(zero), &zero },
      { kSecProtocolItemAttr, sizeof(protocol), &protocol },
      { kSecAuthenticationTypeItemAttr, sizeof(authentication_type), &authentication_type },
  };
  SecKeychainAttributeList attributes = { 7, attrs };
  OSStatus status = SecKeychainItemCreateFromContent(kSecInternetPasswordItemClass,
      &attributes, (UInt32)password_length, password, NULL, access, item);
  if (status != errSecSuccess) return map_status(status);
  return *item ? KC_AUTHORIZED : KC_INTEGRITY;
}

static int delete_just_created_or_integrity(SecKeychainItemRef item, int result) {
  if (!item) return keychain_diagnostic(KC_KEYCHAIN_STAGE_ROLLBACK, KC_INTEGRITY);
  Boolean original_allowed = false;
  int no_ui = begin_without_interaction(&original_allowed);
  if (no_ui != KC_AUTHORIZED) {
    return keychain_diagnostic(KC_KEYCHAIN_STAGE_ROLLBACK, no_ui);
  }
  OSStatus status = SecKeychainItemDelete(item);
  int deletion = status == errSecSuccess ? KC_AUTHORIZED : map_status(status);
  deletion = finish_without_interaction_with_diagnostic(
      original_allowed, deletion, KC_KEYCHAIN_STAGE_ROLLBACK);
  return deletion == KC_AUTHORIZED ? result : deletion;
}

/* This proof is deliberately local to an already-enumerated v2 record.  It
 * holds the no-UI gate across both ACL inspection and the data read, so a
 * record that needs a prompt, has a different owner/ACL multiset, or has no
 * data cannot reach a refresh mutation. */
static int prove_item_access_and_data_without_ui(SecKeychainItemRef item,
                                                 SecAccessRef expected_access,
                                                 int acl_stage, int data_stage) {
  if (!item || !expected_access) return KC_INTEGRITY;
  Boolean original_allowed = false;
  int result = begin_without_interaction(&original_allowed);
  if (result != KC_AUTHORIZED) return keychain_diagnostic(data_stage, result);
  Boolean matches = false;
  result = item_access_matches(item, expected_access, &matches);
  if (result == KC_AUTHORIZED && !matches) result = KC_INTEGRITY;
  if (result != KC_AUTHORIZED) {
    result = keychain_diagnostic(acl_stage, result);
  }
  if (result == KC_AUTHORIZED) {
    UInt32 length = 0;
    void *data = NULL;
    result = copy_data_with_interaction_disabled(item, &length, &data);
    zeroize_and_free_data(length, data);
    if (result == KC_AUTHORIZED && !length) result = KC_INTEGRITY;
    if (result != KC_AUTHORIZED) {
      result = keychain_diagnostic(data_stage, result);
    }
  }
  return finish_without_interaction_with_diagnostic(original_allowed, result, data_stage);
}

/* Re-enumerate after a create or data-only replacement.  The complete tuple
 * must still have exactly one result and it must resolve to the same item;
 * this fails closed on duplicates, metadata drift, or a racing replacement. */
static int reenumerate_same_exact_v2_item(const char *server, const char *account,
                                          SecKeychainItemRef expected,
                                          SecKeychainItemRef *out) {
  if (!server || !account || !expected || !out) return KC_INTEGRITY;
  *out = NULL;
  SecKeychainItemRef exact = NULL;
  int result = exact_v2_item(server, account, &exact);
  if (result != KC_AUTHORIZED) return result;
  if (!exact || !CFEqual(expected, exact)) {
    if (exact) CFRelease(exact);
    return KC_INTEGRITY;
  }
  *out = exact;
  return KC_AUTHORIZED;
}

/* This is the only existing-item mutation.  Passing NULL attributes makes
 * Security.framework atomically replace only the secret bytes: it cannot
 * alter any component of the exact v2 tuple or the sealed ACL. */
static int replace_exact_v2_secret_data(SecKeychainItemRef item,
                                        const unsigned char *password,
                                        size_t password_length) {
  if (!item || !password || !password_length || password_length > 1024) {
    return KC_INTEGRITY;
  }
  OSStatus status = SecKeychainItemModifyAttributesAndData(
      item, NULL, (UInt32)password_length, password);
  return map_status(status);
}

/* The dashboard invokes this only after Rust has used the newly supplied
 * secret in an exact SMB session/share validation.  v1 remains entirely
 * inert: this writer enumerates, reads, modifies, and re-proves only the
 * dedicated v2 tuple. */
int keychain_store_exact_smb_credential(const char *server, const char *account,
                                        const unsigned char *password, size_t password_length,
                                        const char *helper_requirement) {
  if (!server || !account || !password || !password_length || password_length > 1024 ||
      !helper_requirement) return KC_INTEGRITY;
  int result = current_helper_matches_requirement(helper_requirement);
  if (result != KC_AUTHORIZED) {
    return keychain_diagnostic(KC_KEYCHAIN_STAGE_HELPER_REQUIREMENT, result);
  }
  SecTrustedApplicationRef helper = NULL;
  SecAccessRef access = NULL;
  SecAccessRef creation_access = NULL;
  SecKeychainItemRef item = NULL;
  Boolean created = false;
  result = create_requirement_bound_helper(helper_requirement, &helper);
  if (result != KC_AUTHORIZED) {
    result = keychain_diagnostic(KC_KEYCHAIN_STAGE_DURABLE_ACCESS_CONSTRUCTION, result);
    goto done;
  }
  result = create_access(helper, &access);
  if (result != KC_AUTHORIZED) {
    result = keychain_diagnostic(KC_KEYCHAIN_STAGE_DURABLE_ACCESS_CONSTRUCTION, result);
    goto done;
  }

  /* A prior process can crash after creating v2 but before reporting success.
   * It is safe to recover that exact record only after its entire sealed ACL
   * shape and an interaction-free read are independently proven. */
  result = exact_v2_item(server, account, &item);
  if (result == KC_AUTHORIZED) {
    result = prove_item_access_and_data_without_ui(
        item, access, KC_KEYCHAIN_STAGE_GENERATED_ACL_PROOF,
        KC_KEYCHAIN_STAGE_NO_UI_DATA_PROOF);
    if (result != KC_AUTHORIZED) goto done;

    /* One Security.framework operation atomically replaces data only. No
     * attribute or ACL migration, fallback item, or v1 operation is possible. */
    result = replace_exact_v2_secret_data(item, password, password_length);
    if (result != KC_AUTHORIZED) {
      result = keychain_diagnostic(KC_KEYCHAIN_STAGE_DATA_ONLY_REPLACEMENT, result);
      goto done;
    }

    SecKeychainItemRef exact = NULL;
    result = reenumerate_same_exact_v2_item(server, account, item, &exact);
    if (result != KC_AUTHORIZED) {
      result = keychain_diagnostic(KC_KEYCHAIN_STAGE_REENUMERATION_IDENTITY, result);
    }
    if (result == KC_AUTHORIZED) {
      result = prove_item_access_and_data_without_ui(
          exact, access, KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF,
          KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF);
    }
    if (exact) CFRelease(exact);
    goto done;
  }
  if (result != KC_NOT_FOUND) {
    result = keychain_diagnostic(KC_KEYCHAIN_STAGE_V2_ENUMERATION, result);
    goto done;
  }

  /* SecKeychainItemCreateFromContent asks Security.framework to persist its
   * integrity ACL and may mutate the SecAccessRef passed to it in place. Keep
   * the generated three-ACL baseline above immutable for post-create proof;
   * the one-shot creation access is disposable and never used for matching. */
  result = create_access(helper, &creation_access);
  if (result != KC_AUTHORIZED) {
    result = keychain_diagnostic(KC_KEYCHAIN_STAGE_DURABLE_ACCESS_CONSTRUCTION, result);
    goto done;
  }
  result = create_exact_v2_item(server, account, password, password_length,
                                creation_access, &item);
  created = item != NULL;
  if (result != KC_AUTHORIZED || !created) {
    if (result == KC_AUTHORIZED) result = KC_INTEGRITY;
    result = keychain_diagnostic(KC_KEYCHAIN_STAGE_ITEM_CREATION, result);
    goto done;
  }

  SecKeychainItemRef exact = NULL;
  result = reenumerate_same_exact_v2_item(server, account, item, &exact);
  if (result != KC_AUTHORIZED) {
    result = keychain_diagnostic(KC_KEYCHAIN_STAGE_REENUMERATION_IDENTITY, result);
  }
  if (result == KC_AUTHORIZED) {
    /* New records receive the same full-ACL and no-UI data proof as a
     * recovered record before success. Any failure removes only this freshly
     * created v2 record. */
    result = prove_item_access_and_data_without_ui(
        exact, access, KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF,
        KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF);
  }
  if (exact) CFRelease(exact);
done:
  if (created && result != KC_AUTHORIZED) {
    result = delete_just_created_or_integrity(item, result);
  }
  if (item) CFRelease(item);
  if (creation_access) CFRelease(creation_access);
  if (access) CFRelease(access);
  if (helper) CFRelease(helper);
  return result;
}
