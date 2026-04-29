import type { IClient } from "./client.interface";
import type { IEmployees } from "./company.interface";
import type { IProperty } from "./property.interface";

export interface ICreateOrder {
    clientId: number

    city: string
    propertyType: "HOUSE" | "APARTMENT" | "COMMERCIAL"
    dealType: "SELL" | "RENT"
    description: string;
    status: string
}

export interface IAgent {
    id: number,
    username: string,
    avatarUrl: string,
    name: string,
    lastName: string
}
export interface IPropertyOrder {
    id: number;
    propertyId: number;
    status: string
}
export interface IOrder {
    id: number,
    client: IClient,
    agent: IAgent,
    city: string
    propertyType: "HOUSE" | "APARTMENT" | "COMMERCIAL"
    dealType: "SELL" | "RENT"
    description: string
    properties: IPropertyOrder[]
    status: string
}

export interface IOrderUpdate {
    orderId: number,
    data: IOrderDataUpdate
}
export interface IOrderDataUpdate {
    id: number,
    clientId: number,
    agentId: number | undefined,
    city: string
    propertyType: "HOUSE" | "APARTMENT" | "COMMERCIAL"
    dealType: "SELL" | "RENT"
    description: string
    status: string
}

export interface IPropertyOrderStatus {
    status: string
}