export interface ICreateProperty {
    id: number
    cadastralNumber: number
    title: string
    description: string
    propertyType: "HOUSE" | "APARTMENT" | "COMMERCIAL"
    dealType: "SELL" | "RENT"
    address: string
    city: string
    district: string
    price: number
    salePrice: number
    area: number
    rooms: number
    floor: number
    totalFloors: number
    yearBuilt: number
    propertyStatus: "AVAILABLE" | "SOLD" | "RENTED"
}
export interface IProperty {
    id: number
    cadastralNumber: number
    title: string
    description: string
    propertyType: "HOUSE" | "APARTMENT" | "COMMERCIAL"
    dealType: "SELL" | "RENT"
    address: string
    city: string
    district: string
    price: number
    salePrice: number
    area: number
    rooms: number
    floor: number
    totalFloors: number
    yearBuilt: number
    propertyStatus: "AVAILABLE" | "SOLD" | "RENTED"
}
export interface IUpdateProperty {
    title: string
    description: string
    propertyType: "HOUSE" | "APARTMENT" | "COMMERCIAL"
    dealType: "SELL" | "RENT"
    address: string
    city: string
    district: string
    price: number
    salePrice: number
    area: number
    rooms: number
    floor: number
    totalFloors: number
    yearBuilt: number
    propertyStatus: "AVAILABLE" | "SOLD" | "RENTED"
}