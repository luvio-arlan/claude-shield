#ifndef CLAUDE_SHIELD_CORE_H
#define CLAUDE_SHIELD_CORE_H

#include <stdbool.h>
#include <stdint.h>

char *claude_shield_telemetry_json(bool light, bool reset_pool);
char *claude_shield_defenses_json(void);
char *claude_shield_gate_json(bool reset_pool);
char *claude_shield_purity_json(void);
char *claude_shield_patrol_json(bool notify, bool auto_kill);
char *claude_shield_detect_json(int32_t preferred_port);
char *claude_shield_hide_original_json(void);
bool claude_shield_reset_pool(void);
void claude_shield_shutdown(void);
void claude_shield_free_string(char *ptr);

#endif
