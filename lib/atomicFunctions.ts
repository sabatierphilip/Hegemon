export const atomicFunctions = {
  Read: ['read_file', 'read_registry_key', 'read_process_list', 'read_env_var', 'list_directory'],
  MatchCompare: ['match_pattern', 'compare_hash', 'compare_value', 'diff_snapshot'],
  WriteAct: ['write_file', 'patch_registry_key', 'delete_file', 'kill_process'],
  Report: ['flag_finding', 'append_deadrop', 'emit_metric']
};
