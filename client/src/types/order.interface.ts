export interface ICreateOrder {
    clientId: number
    city: string
    propertyType: "HOUSE" | "APARTMENT" | "COMMERCIAL"
    dealType: "SELL" | "RENT"
    description: string
}
export interface IOrder {
    id: number,
    clientId: number
    city: string
    propertyType: "HOUSE" | "APARTMENT" | "COMMERCIAL"
    dealType: "SELL" | "RENT"
    description: string
}