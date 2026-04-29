import { axiosWithAuth } from "@/api/api.interceptors";
import type { ICreateProperty, IUpdateProperty } from "@/types/property.interface";

export const PropertyService = {
    async createProperty(companyId: number, data: ICreateProperty) {
        const { data: responseData } = await axiosWithAuth.post(`company/${companyId}/properties`, data);
        return responseData;
    },
    async getCompanyProperty(companyId: number) {
        const { data } = await axiosWithAuth.get<ICreateProperty[]>(`company/${companyId}/properties`);//не сделано
        return data;
    },

    async getPropertyById(propertyId: number) {
        const { data } = await axiosWithAuth.get<ICreateProperty>(`property/${propertyId}`);
        return data;
    },
    async updateProperty(propertyId: number, data: IUpdateProperty) {
        const { data: responseData } = await axiosWithAuth.put(`property/${propertyId}`, data);
        return responseData;
    },
    async deleteProperty(propertyId: number) {
        const { data: responseData } = await axiosWithAuth.delete(`property/${propertyId}`);
        return responseData;
    },

}