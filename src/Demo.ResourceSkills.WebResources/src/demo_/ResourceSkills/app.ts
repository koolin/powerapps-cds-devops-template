/// <reference path="../../../node_modules/@types/xrm/index.d.ts" />

namespace Demo.ResourceSkils {
    enum Classification {
        Functional = 737670000,
        Technical = 737670001,
        QA = 737670002,
        PM = 737670003,
        TechnologyPlatform = 737670004,
        Training = 737670005,
        Other = 737670006
    }

    function getContactSkillRating() {
        var entityName = parent.Xrm.Page.data.entity.getEntityName();
        if (entityName === "demo_contactskill") {
            var rating = parent.Xrm.Page.getControl<Xrm.Page.NumberControl>("demo_rating");
            return +rating.getValue();
        } else {
            throw ReferenceError("Not executed on demo_contactReference entity");
        }
    }

    export function load() {
        var rating = getContactSkillRating();

        var div = document.getElementById("skill-rank");
        var skillClass = "";
        var iconClass = "";

        switch (rating) {

            case 0: {
                skillClass = "rank-red";
                iconClass = "far fa-circle";
                break;
            }
            case 1: {
                skillClass = "rank-blue";
                iconClass = "fas fa-star-half-alt";
                break;
            }
            case 2: {
                skillClass = "rank-green";
                iconClass = "fas fa-star";
                break;
            }
            default: {
                throw RangeError("contact skill rating out of allowed range 0 - 2");
            }
        }

        div.className += skillClass;
        var font = div.getElementsByTagName("span");
        font[0].className = iconClass;
    }


}