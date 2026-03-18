import { axiosWithAuth } from "@/api/api.interceptors";
import type { ICreateProperty, IUpdateProperty } from "@/types/property.interface";

export const PropertyService = {
    async createProperty(companyId: number, data: ICreateProperty) {
        const { data: responseData } = await axiosWithAuth.post(`company/${companyId}/property/create`, data);
        return responseData;
    },
    async getAllProperty(companyId: number) {
        const { data } = await axiosWithAuth.get<ICreateProperty[]>(`company/${companyId}/properties`);
        return data;
    },
    async getPropertyById(id: number) {
        const { data } = await axiosWithAuth.get<ICreateProperty>(`property/${id}`);
        return data;
    },
    async updateProperty(id: number, data: IUpdateProperty) {
        const { data: responseData } = await axiosWithAuth.put(`property/${id}`, data);
        return responseData;
    }

}