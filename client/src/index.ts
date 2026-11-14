export {
  CalendarServiceClient,
  CalendarServiceError,
  defaultSelection,
  MAX_SELECTED_CALENDARS,
  type AuthorizationWindow,
  type CalendarServiceFailure,
  type CalendarServiceHost,
  type CalendarServiceOptions,
  type CalendarServiceSnapshot,
  type CredentialStore,
  type KeyValueStore,
  type ServiceRequest,
  type ServiceResponse,
  type ServiceTransport,
} from "./client.js";
export type {
  EventBoundary,
  EventFields,
  GoogleCalendar,
  GoogleConnection,
  GoogleEvent,
} from "./schemas.js";
export { eventLinks, type EventLinks } from "./event-links.js";
