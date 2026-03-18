import { PropertyService } from "@/service/property.service";
import type { ICreateProperty, IUpdateProperty } from "@/types/property.interface";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "react-toastify";

export function useCreateProperty(id: number) {
    const qc = useQueryClient();
    const { mutate, isPending } = useMutation({
        mutationKey: ['create-property'],
        mutationFn: (data: ICreateProperty) => PropertyService.createProperty(id, data),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ['property', id] });
            toast.success("Недвижимость успешно создана")
        },
        onError: (error: any) => {
            toast.error(error?.message || "Ошибка при создании недвижимости")
        }
    })
    return { mutate, isPending }
}
export function useGetAllProperty(id: number) {
    return useQuery({
        queryKey: ['property', id],
        queryFn: () => PropertyService.getAllProperty(id),
    })
}
export function useGetPropertyById(id: number) {
    return useQuery({
        queryKey: ['property', id],
        queryFn: () => PropertyService.getPropertyById(id),
    })
}

export function useUpdateProperty(propertyId: number) {
    const qc = useQueryClient();
    const { mutate, isPending } = useMutation({
        mutationKey: ['update-property'],
        mutationFn: (data: IUpdateProperty) => PropertyService.updateProperty(propertyId, data),
        onSuccess: () => {
            qc.invalidateQueries({ queryKey: ['property', propertyId] });
            toast.success("Недвижимость успешно обновлена")
        },
        onError: (error: any) => {
            toast.error(error?.message || "Ошибка при обновлении недвижимости")
        }
    })
    return { mutate, isPending }
}