import { Card, CardContent } from "@/components/ui/card"
import type { IProperty } from "@/types/property.interface"
interface Props {
    properties: IProperty[] | undefined
}
export default function PropertyStats({ properties }: Props) {

    return (
        <div className="grid grid-cols-3 gap-4">

            <Card>
                <CardContent className="p-4">
                    <p className="text-sm text-muted-foreground">
                        Всего объектов
                    </p>

                    <p className="text-xl font-semibold">
                        {properties?.length ?? 0}
                    </p>
                </CardContent>
            </Card>

            <Card>
                <CardContent className="p-4">
                    <p className="text-sm text-muted-foreground">
                        В продаже
                    </p>

                    <p className="text-xl font-semibold">
                        {properties?.filter((p: { propertyStatus: string }) => p.propertyStatus === "AVAILABLE").length}
                    </p>
                </CardContent>
            </Card>

            <Card>
                <CardContent className="p-4">
                    <p className="text-sm text-muted-foreground">
                        Продано
                    </p>

                    <p className="text-xl font-semibold">
                        {properties?.filter((p: { propertyStatus: string }) => p.propertyStatus === "SOLD").length}
                    </p>
                </CardContent>
            </Card>

        </div>
    )
}