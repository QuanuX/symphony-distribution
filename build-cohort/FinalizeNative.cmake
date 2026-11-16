cmake_minimum_required(VERSION 3.30)
# Runs inside the existing owner finalization hook, before its receipt is sealed.
if(NOT IS_ABSOLUTE "$ENV{SYMPHONY_D06_PYTHON}" OR NOT EXISTS "$ENV{SYMPHONY_D06_PYTHON}")
  message(FATAL_ERROR "Explicit D06 Python interpreter is required")
endif()
set(arguments --root "${SYMPHONY_PACKAGE_ROOT}")
foreach(spec IN LISTS SYMPHONY_PACKAGE_OWNED_SPECS)
  list(APPEND arguments --owned "${spec}")
endforeach()
execute_process(COMMAND "$ENV{SYMPHONY_D06_PYTHON}"
  "${CMAKE_CURRENT_LIST_DIR}/finalize_native.py" ${arguments}
  TIMEOUT 240 COMMAND_ERROR_IS_FATAL ANY)
