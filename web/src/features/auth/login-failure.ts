const LOGIN_FAILURE_MESSAGE_KEYS: Record<string, string> = {
  accountDisabled: 'apiError.auth.accountDisabled',
  linkRequired: 'login.failure.linkRequired',
  casInvalidState: 'login.failure.casInvalidState',
  casTicketMissing: 'login.failure.casTicketMissing',
  casValidationFailed: 'login.failure.casValidationFailed',
  casUnavailable: 'login.failure.casUnavailable',
  internalError: 'login.failure.internalError',
}

export function loginFailureMessageKey(reason?: string) {
  return reason ? LOGIN_FAILURE_MESSAGE_KEYS[reason] : undefined
}
