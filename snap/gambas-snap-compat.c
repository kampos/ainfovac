#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int (*real_chown)(const char *path, uid_t owner, gid_t group);
static int (*real_lchown)(const char *path, uid_t owner, gid_t group);
static int (*real_fchown)(int fd, uid_t owner, gid_t group);
static int (*real_fchownat)(int dirfd, const char *path, uid_t owner, gid_t group, int flags);
static struct passwd *(*real_getpwuid)(uid_t uid);
static int (*real_getpwuid_r)(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);
static struct passwd *(*real_getpwnam)(const char *name);
static int (*real_getpwnam_r)(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);

static void init_real_functions(void)
{
  if (!real_chown)
    real_chown = dlsym(RTLD_NEXT, "chown");
  if (!real_lchown)
    real_lchown = dlsym(RTLD_NEXT, "lchown");
  if (!real_fchown)
    real_fchown = dlsym(RTLD_NEXT, "fchown");
  if (!real_fchownat)
    real_fchownat = dlsym(RTLD_NEXT, "fchownat");
  if (!real_getpwuid)
    real_getpwuid = dlsym(RTLD_NEXT, "getpwuid");
  if (!real_getpwuid_r)
    real_getpwuid_r = dlsym(RTLD_NEXT, "getpwuid_r");
  if (!real_getpwnam)
    real_getpwnam = dlsym(RTLD_NEXT, "getpwnam");
  if (!real_getpwnam_r)
    real_getpwnam_r = dlsym(RTLD_NEXT, "getpwnam_r");
}


__attribute__((constructor))
static void ainfovac_compat_loaded(void)
{
  fprintf(stderr,
          "ainfovac-compat: loaded uid=%ld gid=%ld HOME=%s redirected-home=%s\n",
          (long)getuid(), (long)getgid(),
          getenv("HOME") ? getenv("HOME") : "(unset)",
          getenv("AINFOVAC_SNAP_HOME") ? getenv("AINFOVAC_SNAP_HOME") : "(unset)");
}

static const char *snap_home(void)
{
  const char *home;

  home = getenv("AINFOVAC_SNAP_HOME");
  if (!home || !home[0])
    home = getenv("HOME");
  if (!home || !home[0])
    return NULL;

  return home;
}

static const char *snap_home_for_uid(uid_t uid)
{
  if (uid != getuid())
    return NULL;

  return snap_home();
}

static const char *snap_home_for_name(const char *name)
{
  struct passwd *pwd;

  if (!name || !name[0])
    return NULL;

  init_real_functions();
  pwd = real_getpwuid(getuid());
  if (!pwd || strcmp(name, pwd->pw_name) != 0)
    return NULL;

  return snap_home();
}

static size_t passwd_buffer_used(const struct passwd *pwd, const char *buf, size_t buflen)
{
  const char *fields[] = {pwd->pw_name, pwd->pw_passwd, pwd->pw_gecos, pwd->pw_dir, pwd->pw_shell};
  const char *end = buf;
  size_t i;

  for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
    if (fields[i] >= buf && fields[i] < buf + buflen) {
      const char *field_end = fields[i] + strlen(fields[i]) + 1;
      if (field_end > end)
        end = field_end;
    }
  }

  return (size_t)(end - buf);
}

static bool can_ignore_chown_failure(const struct stat *st, uid_t owner, gid_t group)
{
  uid_t uid = getuid();
  gid_t gid = getgid();

  if (!S_ISDIR(st->st_mode))
    return false;
  if (st->st_uid != uid || st->st_gid != gid)
    return false;
  if (owner != uid || group != gid)
    return false;
  return true;
}

static int maybe_tolerate_failure(int result, int saved_errno,
                                  const char *operation,
                                  const struct stat *st,
                                  uid_t owner, gid_t group)
{
  if (result == 0)
    return 0;

  /* AppArmor reports denied ownership changes as EACCES; other
     confinement layers may use EPERM. Never fake a real owner change:
     only accept the operation when ownership already matches. */
  if ((saved_errno != EACCES && saved_errno != EPERM) || !st ||
      !can_ignore_chown_failure(st, owner, group)) {
    errno = saved_errno;
    return result;
  }

  fprintf(stderr,
          "ainfovac-compat: ignored denied %s; ownership already %ld:%ld\n",
          operation, (long)st->st_uid, (long)st->st_gid);
  errno = 0;
  return 0;
}

int chown(const char *path, uid_t owner, gid_t group)
{
  struct stat st;
  bool have_stat = lstat(path, &st) == 0;
  int result;
  int saved_errno;

  init_real_functions();
  result = real_chown(path, owner, group);
  saved_errno = errno;
  return maybe_tolerate_failure(result, saved_errno, "chown",
                                have_stat ? &st : NULL, owner, group);
}

int lchown(const char *path, uid_t owner, gid_t group)
{
  struct stat st;
  bool have_stat = lstat(path, &st) == 0;
  int result;
  int saved_errno;

  init_real_functions();
  result = real_lchown(path, owner, group);
  saved_errno = errno;
  return maybe_tolerate_failure(result, saved_errno, "lchown",
                                have_stat ? &st : NULL, owner, group);
}

int fchown(int fd, uid_t owner, gid_t group)
{
  struct stat st;
  bool have_stat = fstat(fd, &st) == 0;
  int result;
  int saved_errno;

  init_real_functions();
  result = real_fchown(fd, owner, group);
  saved_errno = errno;
  return maybe_tolerate_failure(result, saved_errno, "fchown",
                                have_stat ? &st : NULL, owner, group);
}

int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags)
{
  struct stat st;
  bool have_stat = fstatat(dirfd, path, &st, flags) == 0;
  int result;
  int saved_errno;

  init_real_functions();
  result = real_fchownat(dirfd, path, owner, group, flags);
  saved_errno = errno;
  return maybe_tolerate_failure(result, saved_errno, "fchownat",
                                have_stat ? &st : NULL, owner, group);
}

struct passwd *getpwuid(uid_t uid)
{
  static struct passwd redirected_pwd;
  static char redirected_home[PATH_MAX];
  struct passwd *pwd;
  const char *home;

  init_real_functions();
  pwd = real_getpwuid(uid);
  home = snap_home_for_uid(uid);
  if (!pwd || !home)
    return pwd;

  redirected_pwd = *pwd;
  snprintf(redirected_home, sizeof(redirected_home), "%s", home);
  redirected_pwd.pw_dir = redirected_home;
  return &redirected_pwd;
}

struct passwd *getpwnam(const char *name)
{
  static struct passwd redirected_pwd;
  static char redirected_home[PATH_MAX];
  struct passwd *pwd;
  const char *home;

  init_real_functions();
  pwd = real_getpwnam(name);
  home = snap_home_for_name(name);
  if (!pwd || !home)
    return pwd;

  redirected_pwd = *pwd;
  snprintf(redirected_home, sizeof(redirected_home), "%s", home);
  redirected_pwd.pw_dir = redirected_home;
  return &redirected_pwd;
}

int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result)
{
  const char *home;
  size_t used;
  size_t home_len;
  int ret;

  init_real_functions();
  ret = real_getpwuid_r(uid, pwd, buf, buflen, result);
  home = snap_home_for_uid(uid);
  if (ret != 0 || !*result || !home)
    return ret;

  used = passwd_buffer_used(pwd, buf, buflen);
  home_len = strlen(home) + 1;
  if (used + home_len > buflen)
    return ERANGE;

  memcpy(buf + used, home, home_len);
  pwd->pw_dir = buf + used;
  return 0;
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result)
{
  const char *home;
  size_t used;
  size_t home_len;
  int ret;

  init_real_functions();
  ret = real_getpwnam_r(name, pwd, buf, buflen, result);
  home = snap_home_for_name(name);
  if (ret != 0 || !*result || !home)
    return ret;

  used = passwd_buffer_used(pwd, buf, buflen);
  home_len = strlen(home) + 1;
  if (used + home_len > buflen)
    return ERANGE;

  memcpy(buf + used, home, home_len);
  pwd->pw_dir = buf + used;
  return 0;
}
