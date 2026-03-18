import { Badge } from "@/components/ui/badge"
import type { IProperty } from "@/types/property.interface"
interface Props {
    property: IProperty
}
export default function PropertyHeader({ property }: Props) {

    return (

        <div className="flex justify-between items-center">

            <div>

                <h1 className="text-2xl font-bold">
                    {property.title}
                </h1>

                <p className="text-muted-foreground">
                    {property.city}, {property.address}
                </p>

            </div>

            <Badge>
                {property.propertyStatus}
            </Badge>

        </div>

    )
}