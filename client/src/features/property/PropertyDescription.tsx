import { Card, CardContent } from "@/components/ui/card"
import type { IProperty } from "@/types/property.interface"

interface Props {
    property: IProperty
}

export default function PropertyDescription({ property }: Props) {

    if (!property.description) return null

    return (
        <Card>
            <CardContent className="p-6">

                <h2 className="text-lg font-semibold mb-2">
                    Описание
                </h2>

                <p className="text-muted-foreground whitespace-pre-line">
                    {property.description}
                </p>

            </CardContent>
        </Card>
    )
}