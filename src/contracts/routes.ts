import { z } from "zod";

import {
  DeviceSessionIdSchema,
  EmptyObjectSchema,
  TransactionIdSchema,
  UuidSchema,
} from "./common";
import {
  CalendarsResponseSchema,
  ConnectionsResponseSchema,
  DevicesResponseSchema,
  EventsQuerySchema,
  EventsResponseSchema,
  SessionSchema,
} from "./resources";
import {
  ConnectRedeemResponseSchema,
  ProviderCallbackQuerySchema,
  SignInRedeemResponseSchema,
  TransactionRedeemRequestSchema,
  TransactionStartRequestSchema,
  TransactionStartResponseSchema,
  TransactionStatusQuerySchema,
  TransactionStatusResponseSchema,
} from "./transactions";

export const HealthResponseSchema = z.strictObject({ status: z.enum(["ok", "ready"]) });
export const CallbackResponseSchema = z.strictObject({ status: z.literal("complete") });

export const ROUTE_NAMES = [
  "healthLive",
  "healthReady",
  "signInStart",
  "signInStatus",
  "signInRedeem",
  "connectStart",
  "connectStatus",
  "connectRedeem",
  "session",
  "connections",
  "disconnect",
  "calendars",
  "events",
  "devices",
  "revokeDevice",
  "deleteAccount",
  "providerCallback",
] as const;

export type RouteName = (typeof ROUTE_NAMES)[number];
export type HttpMethod = "GET" | "POST" | "DELETE";

export interface RouteDefinition {
  readonly name: RouteName;
  readonly method: HttpMethod;
  readonly path: string;
  readonly authenticated: boolean;
  readonly body?: z.ZodType;
  readonly query: z.ZodType;
  readonly params: Readonly<Record<string, z.ZodType>>;
  readonly response?: z.ZodType;
  readonly successStatus: number;
}

const noParams = {} as const;
const transactionParams = { transaction_id: TransactionIdSchema } as const;

export const routes: readonly RouteDefinition[] = [
  {
    name: "healthLive",
    method: "GET",
    path: "/health/live",
    authenticated: false,
    query: EmptyObjectSchema,
    params: noParams,
    response: HealthResponseSchema,
    successStatus: 200,
  },
  {
    name: "healthReady",
    method: "GET",
    path: "/health/ready",
    authenticated: false,
    query: EmptyObjectSchema,
    params: noParams,
    response: HealthResponseSchema,
    successStatus: 200,
  },
  {
    name: "signInStart",
    method: "POST",
    path: "/v1/sign-in/start",
    authenticated: false,
    body: TransactionStartRequestSchema,
    query: EmptyObjectSchema,
    params: noParams,
    response: TransactionStartResponseSchema,
    successStatus: 201,
  },
  {
    name: "signInStatus",
    method: "GET",
    path: "/v1/sign-in/{transaction_id}/status",
    authenticated: false,
    query: TransactionStatusQuerySchema,
    params: transactionParams,
    response: TransactionStatusResponseSchema,
    successStatus: 200,
  },
  {
    name: "signInRedeem",
    method: "POST",
    path: "/v1/sign-in/{transaction_id}/redeem",
    authenticated: false,
    body: TransactionRedeemRequestSchema,
    query: EmptyObjectSchema,
    params: transactionParams,
    response: SignInRedeemResponseSchema,
    successStatus: 200,
  },
  {
    name: "connectStart",
    method: "POST",
    path: "/v1/connections/google/start",
    authenticated: true,
    body: TransactionStartRequestSchema,
    query: EmptyObjectSchema,
    params: noParams,
    response: TransactionStartResponseSchema,
    successStatus: 201,
  },
  {
    name: "connectStatus",
    method: "GET",
    path: "/v1/connections/google/{transaction_id}/status",
    authenticated: true,
    query: TransactionStatusQuerySchema,
    params: transactionParams,
    response: TransactionStatusResponseSchema,
    successStatus: 200,
  },
  {
    name: "connectRedeem",
    method: "POST",
    path: "/v1/connections/google/{transaction_id}/redeem",
    authenticated: true,
    body: TransactionRedeemRequestSchema,
    query: EmptyObjectSchema,
    params: transactionParams,
    response: ConnectRedeemResponseSchema,
    successStatus: 200,
  },
  {
    name: "session",
    method: "GET",
    path: "/v1/session",
    authenticated: true,
    query: EmptyObjectSchema,
    params: noParams,
    response: SessionSchema,
    successStatus: 200,
  },
  {
    name: "connections",
    method: "GET",
    path: "/v1/connections",
    authenticated: true,
    query: EmptyObjectSchema,
    params: noParams,
    response: ConnectionsResponseSchema,
    successStatus: 200,
  },
  {
    name: "disconnect",
    method: "DELETE",
    path: "/v1/connections/{connection_id}",
    authenticated: true,
    query: EmptyObjectSchema,
    params: { connection_id: UuidSchema },
    successStatus: 204,
  },
  {
    name: "calendars",
    method: "GET",
    path: "/v1/calendars",
    authenticated: true,
    query: EmptyObjectSchema,
    params: noParams,
    response: CalendarsResponseSchema,
    successStatus: 200,
  },
  {
    name: "events",
    method: "GET",
    path: "/v1/calendars/{calendar_id}/events",
    authenticated: true,
    query: EventsQuerySchema,
    params: { calendar_id: UuidSchema },
    response: EventsResponseSchema,
    successStatus: 200,
  },
  {
    name: "devices",
    method: "GET",
    path: "/v1/devices",
    authenticated: true,
    query: EmptyObjectSchema,
    params: noParams,
    response: DevicesResponseSchema,
    successStatus: 200,
  },
  {
    name: "revokeDevice",
    method: "DELETE",
    path: "/v1/devices/{device_id}",
    authenticated: true,
    query: EmptyObjectSchema,
    params: { device_id: DeviceSessionIdSchema },
    successStatus: 204,
  },
  {
    name: "deleteAccount",
    method: "DELETE",
    path: "/v1/account",
    authenticated: true,
    query: EmptyObjectSchema,
    params: noParams,
    successStatus: 204,
  },
  {
    name: "providerCallback",
    method: "GET",
    path: "/oauth/google/callback",
    authenticated: false,
    query: ProviderCallbackQuerySchema,
    params: noParams,
    response: CallbackResponseSchema,
    successStatus: 200,
  },
];
