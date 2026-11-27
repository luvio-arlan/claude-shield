#ifndef CLAUDE_SHIELD_CORE_H
#define CLAUDE_SHIELD_CORE_H

#include <stdbool.h>
#include <stdint.h>

char *claude_shield_telemetry_json(bool light, bool reset_pool, bool skip_api);
char *claude_shield_defenses_json(void);
char *claude_shield_gate_json(bool reset_pool);
char *claude_shield_purity_json(void);
char *claude_shield_patrol_json(bool notify, bool auto_kill);
char *claude_shield_detect_json(int32_t preferred_port);
char *claude_shield_hide_original_json(void);
char *claude_shield_launch_desktop_json(bool skip_gate, const char *verified_ip);
char *claude_shield_kill_claude_json(bool include_cli);
char *claude_shield_kill_pids_json(const char *csv_pids);
bool claude_shield_reset_pool(void);
void claude_shield_shutdown(void);
void claude_shield_free_string(char *ptr);

#endif
