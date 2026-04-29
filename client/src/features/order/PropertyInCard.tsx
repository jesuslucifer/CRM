import { useUpdateOrderPropertyStatus } from "@/shared/hooks/useOrder"
import { useGetPropertyById } from "@/shared/hooks/useProperty"
import type { IPropertyOrder, IPropertyOrderStatus } from "@/types/order.interface"

import {
    Select,
    SelectTrigger,
    SelectValue,
    SelectContent,
    SelectItem
} from "@/components/ui/select"

interface Props {
    orderId: number,
    property: IPropertyOrder
}

export default function PropertyInCard({ orderId, property }: Props) {

    const { data } = useGetPropertyById(property.propertyId)

    const { mutate: updatePropertyStatus, isPending } =
        useUpdateOrderPropertyStatus(orderId, property.propertyId)

    if (!data) return null

    const handleChange = (value: string) => {
        if (String(value) === property.status) return

        updatePropertyStatus({
            status: value
        })
    }

    return (
        <div className="border rounded-xl p-3 bg-white hover:shadow-sm transition space-y-3">

            <div className="flex justify-between items-start gap-2">

                <div>
                    <p className="text-sm font-medium">
                        {data.title}
                    </p>

                    <p className="text-xs text-muted-foreground">
                        {data.city}, {data.address}
                    </p>
                </div>

                {/* 🔥 SELECT ВМЕСТО BADGE */}
                <Select
                    defaultValue={property.status}
                    onValueChange={handleChange}
                    disabled={isPending}
                >
                    <SelectTrigger className="h-7 text-xs w-[130px]">
                        <SelectValue />
                    </SelectTrigger>

                    <SelectContent>

                        <SelectItem value="SELECTION">
                            Подбор
                        </SelectItem>

                        <SelectItem value="SHOW_ONLINE">
                            Онлайн показ
                        </SelectItem>

                        <SelectItem value="SHOW_OFFLINE">
                            Оффлайн показ
                        </SelectItem>

                        <SelectItem value="DEAL">
                            Сделка
                        </SelectItem>

                    </SelectContent>

                </Select>

            </div>

            <div className="flex justify-between text-xs text-muted-foreground">
                <span>{data.rooms} комн.</span>
                <span>{data.floor}/{data.totalFloors}</span>
                <span className="font-medium text-black">
                    {data.price} ₽
                </span>
            </div>

        </div>
    )
}