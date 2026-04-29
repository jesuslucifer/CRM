export interface IClient {
    id: number
    firstName: string,
    lastName: string,
    phone: number,
    email: string,
    clientType: string,
    clientSource: string,
    notes: string
}
export interface IClientResponse {
    id: number,
    firstName: string,
    lastName: string,
    phone: number,
    email: string,
    clientType: string,
    clientSource: string,
    notes: string
}