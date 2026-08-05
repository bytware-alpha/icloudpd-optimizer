#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <sys/xattr.h>

int authorization_policy_has_quarantine(const char *path) {
  if (getxattr(path, "com.apple.quarantine", NULL, 0, 0, 0) >= 0) return 1;
  if (errno == ENOATTR) return 0;
  return -1;
}

static Boolean make_string(const char *value, CFStringRef *out) {
  *out = CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
  return *out != NULL;
}

/* SecRequirementCreateWithString accepts the expression, while csreq's
 * canonical designated-requirement rendering prefixes it with "designated => ". */
static const char *requirement_expression(const char *value) {
  const char *prefix = "designated => ";
  const char *p = value;
  while (*prefix && *p == *prefix) { ++p; ++prefix; }
  return *prefix ? value : p;
}

int authorization_policy_validate_static_code(const char *path, const char *requirement) {
  CFStringRef path_string = NULL, requirement_string = NULL;
  CFURLRef url = NULL;
  SecStaticCodeRef code = NULL;
  SecRequirementRef parsed_requirement = NULL;
  OSStatus status = errSecParam;
  int result = 0;
  if (!make_string(path, &path_string) || !make_string(requirement_expression(requirement), &requirement_string)) goto done;
  url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path_string, kCFURLPOSIXPathStyle, true);
  if (!url) goto done;
  status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
  if (status != errSecSuccess) goto done;
  status = SecRequirementCreateWithString(requirement_string, kSecCSDefaultFlags, &parsed_requirement);
  if (status != errSecSuccess) goto done;
  status = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, parsed_requirement);
  result = status == errSecSuccess ? 1 : 0;
done:
  if (parsed_requirement) CFRelease(parsed_requirement);
  if (code) CFRelease(code);
  if (url) CFRelease(url);
  if (path_string) CFRelease(path_string);
  if (requirement_string) CFRelease(requirement_string);
  return result;
}
