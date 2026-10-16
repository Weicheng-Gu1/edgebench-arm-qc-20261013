// Trusted compatibility observer, never supplied as a learner implementation.
#include "json.hpp"
#include <BRepPrimAPI_MakeBox.hxx>
#include <BRepPrimAPI_MakeSphere.hxx>
#include <BRepPrimAPI_MakeCylinder.hxx>
#include <BRepPrimAPI_MakeCone.hxx>
#include <BRepPrimAPI_MakeTorus.hxx>
#include <BRepPrimAPI_MakePrism.hxx>
#include <BRepPrimAPI_MakeRevol.hxx>
#include <BRepFilletAPI_MakeFillet.hxx>
#include <BRepOffsetAPI_MakeOffsetShape.hxx>
#include <BRepOffsetAPI_ThruSections.hxx>
#include <BRepOffsetAPI_MakePipe.hxx>
#include <BRepOffsetAPI_MakePipeShell.hxx>
#include <BRepTools.hxx>
#include <BRepBuilderAPI_MakeEdge.hxx>
#include <BRepBuilderAPI_MakeWire.hxx>
#include <BRepBuilderAPI_MakeSolid.hxx>
#include <BRepLib.hxx>
#include <BRepBuilderAPI_MakePolygon.hxx>
#include <BRepBuilderAPI_MakeFace.hxx>
#include <BRepBuilderAPI_MakeVertex.hxx>
#include <BRepBuilderAPI_Transform.hxx>
#include <BRepBuilderAPI_Sewing.hxx>
#include <BRepAlgoAPI_Fuse.hxx>
#include <BRepAlgoAPI_Cut.hxx>
#include <BRepAlgoAPI_Common.hxx>
#include <BRepAlgoAPI_Section.hxx>
#include <BRepCheck_Analyzer.hxx>
#include <BRepClass3d_SolidClassifier.hxx>
#include <BRepExtrema_DistShapeShape.hxx>
#include <BRepGProp.hxx>
#include <BRepBndLib.hxx>
#include <BRepMesh_IncrementalMesh.hxx>
#include <BRepAdaptor_Curve.hxx>
#include <BRep_Tool.hxx>
#include <BRep_Builder.hxx>
#include <TopoDS_Compound.hxx>
#include <Bnd_Box.hxx>
#include <GProp_GProps.hxx>
#include <Geom_Line.hxx>
#include <Geom_Circle.hxx>
#include <Geom_Ellipse.hxx>
#include <Geom_BezierCurve.hxx>
#include <Geom_BSplineCurve.hxx>
#include <Geom_Plane.hxx>
#include <Geom_SphericalSurface.hxx>
#include <Geom_CylindricalSurface.hxx>
#include <Geom_ConicalSurface.hxx>
#include <Geom_ToroidalSurface.hxx>
#include <Geom_BezierSurface.hxx>
#include <Geom_BSplineSurface.hxx>
#include <GeomAPI_ProjectPointOnCurve.hxx>
#include <GeomAPI_ProjectPointOnSurf.hxx>
#include <GeomAdaptor_Curve.hxx>
#include <GCPnts_AbscissaPoint.hxx>
#include <GeomLProp_SLProps.hxx>
#include <ShapeFix_Shape.hxx>
#include <ShapeUpgrade_UnifySameDomain.hxx>
#include <TopExp_Explorer.hxx>
#include <TopExp.hxx>
#include <TopoDS.hxx>
#include <TopTools_IndexedMapOfShape.hxx>
#include <TColgp_Array1OfPnt.hxx>
#include <TColgp_Array2OfPnt.hxx>
#include <TColStd_Array1OfReal.hxx>
#include <TColStd_Array2OfReal.hxx>
#include <TColStd_Array1OfInteger.hxx>
#include <Poly_Triangulation.hxx>
#include <Standard_Failure.hxx>
#include <gp_Quaternion.hxx>
#include <cmath>
#include <iostream>
#include <map>
#include <string>
using nlohmann::json;

static gp_Pnt point(const json& a){return gp_Pnt(a.at(0).get<double>(),a.at(1).get<double>(),a.at(2).get<double>());}
static gp_Vec vec(const json& a){return gp_Vec(a.at(0).get<double>(),a.at(1).get<double>(),a.at(2).get<double>());}
static json xyz(const gp_Pnt& p){return {p.X(),p.Y(),p.Z()};}
static json xyz(const gp_Vec& p){return {p.X(),p.Y(),p.Z()};}
static gp_Ax2 axes(const json& a){return gp_Ax2(point(a.value("origin",json::array({0,0,0}))),gp_Dir(vec(a.value("axis",json::array({0,0,1})))),gp_Dir(vec(a.value("x_axis",json::array({1,0,0})))));}
static TColStd_Array1OfReal reals(const json& a){TColStd_Array1OfReal r(1,a.size());for(unsigned i=0;i<a.size();i++)r(i+1)=a[i].get<double>();return r;}
static TColStd_Array1OfInteger ints(const json& a){TColStd_Array1OfInteger r(1,a.size());for(unsigned i=0;i<a.size();i++)r(i+1)=a[i].get<int>();return r;}

static Handle(Geom_Curve) make_curve(const json& a){
    std::string kind=a.at("kind");
    if(kind=="line")return new Geom_Line(point(a.at("origin")),gp_Dir(vec(a.at("direction"))));
    if(kind=="circle")return new Geom_Circle(axes(a),a.at("radius").get<double>());
    if(kind=="ellipse")return new Geom_Ellipse(axes(a),a.at("major").get<double>(),a.at("minor").get<double>());
    auto data=a.at("poles");TColgp_Array1OfPnt poles(1,data.size());for(unsigned i=0;i<data.size();i++)poles(i+1)=point(data[i]);
    if(kind=="bezier"){
        if(a.contains("weights"))return new Geom_BezierCurve(poles,reals(a.at("weights")));
        return new Geom_BezierCurve(poles);
    }
    if(kind=="bspline"){
        auto knots=reals(a.at("knots"));auto mults=ints(a.at("multiplicities"));int degree=a.at("degree");bool periodic=a.value("periodic",false);
        if(a.contains("weights"))return new Geom_BSplineCurve(poles,reals(a.at("weights")),knots,mults,degree,periodic);
        return new Geom_BSplineCurve(poles,knots,mults,degree,periodic);
    }
    throw std::runtime_error("Unsupported curve");
}

static json curve_job(const json& job){
    auto curve=make_curve(job.at("curve"));json samples=json::array(),projects=json::array();
    for(auto& t:job.value("parameters",json::array())){
        gp_Pnt p;gp_Vec d1,d2;curve->D2(t.get<double>(),p,d1,d2);
        double denominator=std::pow(d1.Magnitude(),3.);
        samples.push_back({{"point",xyz(p)},{"d1",xyz(d1)},{"d2",xyz(d2)},
                           {"curvature",denominator>1e-30?json(d1.Crossed(d2).Magnitude()/denominator):json(nullptr)}});
    }
    json result={{"ok",true},{"samples",samples}};
    if(job.contains("length_interval")){
        auto interval=job.at("length_interval");GeomAdaptor_Curve adaptor(curve);
        result["length"]=GCPnts_AbscissaPoint::Length(adaptor,interval[0].get<double>(),interval[1].get<double>(),1e-10);
    }
    for(auto& p:job.value("project",json::array())){
        auto interval=job.at("projection_interval");GeomAPI_ProjectPointOnCurve projection(point(p),curve,interval[0].get<double>(),interval[1].get<double>());
        if(!projection.NbPoints())projects.push_back({{"found",false}});
        else projects.push_back({{"found",true},{"parameter",projection.LowerDistanceParameter()},{"point",xyz(projection.NearestPoint())},{"distance",projection.LowerDistance()}});
    }
    result["projections"]=projects;return result;
}

static Handle(Geom_Surface) make_surface(const json& a){
    std::string kind=a.at("kind");
    if(kind=="plane")return new Geom_Plane(gp_Ax3(axes(a)));
    if(kind=="sphere")return new Geom_SphericalSurface(gp_Ax3(axes(a)),a.at("radius").get<double>());
    if(kind=="cylinder")return new Geom_CylindricalSurface(gp_Ax3(axes(a)),a.at("radius").get<double>());
    if(kind=="cone")return new Geom_ConicalSurface(gp_Ax3(axes(a)),a.at("semi_angle").get<double>(),a.at("radius").get<double>());
    if(kind=="torus")return new Geom_ToroidalSurface(gp_Ax3(axes(a)),a.at("major").get<double>(),a.at("minor").get<double>());
    auto data=a.at("poles");int nu=data.size(),nv=data.at(0).size();TColgp_Array2OfPnt poles(1,nu,1,nv);
    for(int i=0;i<nu;i++)for(int j=0;j<nv;j++)poles(i+1,j+1)=point(data[i][j]);
    if(kind=="bezier"){
        if(!a.contains("weights"))return new Geom_BezierSurface(poles);
        TColStd_Array2OfReal weights(1,nu,1,nv);for(int i=0;i<nu;i++)for(int j=0;j<nv;j++)weights(i+1,j+1)=a.at("weights")[i][j].get<double>();
        return new Geom_BezierSurface(poles,weights);
    }
    if(kind=="bspline"){
        auto uk=reals(a.at("u_knots")),vk=reals(a.at("v_knots"));auto um=ints(a.at("u_multiplicities")),vm=ints(a.at("v_multiplicities"));
        int ud=a.at("u_degree"),vd=a.at("v_degree");bool up=a.value("u_periodic",false),vp=a.value("v_periodic",false);
        if(!a.contains("weights"))return new Geom_BSplineSurface(poles,uk,vk,um,vm,ud,vd,up,vp);
        TColStd_Array2OfReal weights(1,nu,1,nv);for(int i=0;i<nu;i++)for(int j=0;j<nv;j++)weights(i+1,j+1)=a.at("weights")[i][j].get<double>();
        return new Geom_BSplineSurface(poles,weights,uk,vk,um,vm,ud,vd,up,vp);
    }
    throw std::runtime_error("Unsupported surface");
}

static json surface_job(const json& job){
    auto surface=make_surface(job.at("surface"));json samples=json::array(),projects=json::array();
    for(auto& uv:job.value("parameters",json::array())){
        double u=uv[0].get<double>(),v=uv[1].get<double>();gp_Pnt p;gp_Vec du,dv,duu,dvv,duv;
        surface->D2(u,v,p,du,dv,duu,dvv,duv);GeomLProp_SLProps properties(surface,u,v,2,1e-10);
        json normal=nullptr,mean=nullptr,gaussian=nullptr;
        if(properties.IsNormalDefined())normal=xyz(gp_Vec(properties.Normal()));
        if(properties.IsCurvatureDefined()){mean=properties.MeanCurvature();gaussian=properties.GaussianCurvature();}
        samples.push_back({{"point",xyz(p)},{"du",xyz(du)},{"dv",xyz(dv)},{"duu",xyz(duu)},
                           {"dvv",xyz(dvv)},{"duv",xyz(duv)},{"normal",normal},{"mean_curvature",mean},{"gaussian_curvature",gaussian}});
    }
    for(auto& p:job.value("project",json::array())){
        auto bounds=job.at("projection_bounds");GeomAPI_ProjectPointOnSurf projection(point(p),surface,bounds[0].get<double>(),bounds[1].get<double>(),bounds[2].get<double>(),bounds[3].get<double>(),1e-10);
        if(!projection.NbPoints())projects.push_back({{"found",false}});
        else{double u,v;projection.LowerDistanceParameters(u,v);projects.push_back({{"found",true},{"parameters",{u,v}},{"point",xyz(projection.NearestPoint())},{"distance",projection.LowerDistance()}});}
    }
    return {{"ok",true},{"samples",samples},{"projections",projects}};
}

static TopoDS_Face polygon_face(const json& a){
    BRepBuilderAPI_MakePolygon outer;for(auto& p:a.at("outer"))outer.Add(point(p));outer.Close();
    BRepBuilderAPI_MakeFace builder(outer.Wire());
    for(auto& hole:a.value("holes",json::array())){BRepBuilderAPI_MakePolygon wire;for(auto& p:hole)wire.Add(point(p));wire.Close();builder.Add(wire.Wire());}
    return builder.Face();
}
static json shape_observation(const TopoDS_Shape& shape,const json& request){
    GProp_GProps mass,area;BRepGProp::VolumeProperties(shape,mass);BRepGProp::SurfaceProperties(shape,area);
    json result={{"valid_topology",bool(BRepCheck_Analyzer(shape).IsValid())},{"volume",mass.Mass()},
                 {"area",area.Mass()},{"center_of_mass",xyz(mass.CentreOfMass())}};
    json integrals=json::array();
    for(double eps:{1e-6,1e-8,1e-10,1e-12}){
        GProp_GProps adaptive_mass,adaptive_area;
        double volume_error=BRepGProp::VolumeProperties(shape,adaptive_mass,eps);
        double area_error=BRepGProp::SurfaceProperties(shape,adaptive_area,eps);
        integrals.push_back({{"method","adaptive_gauss"},{"eps",eps},{"volume",adaptive_mass.Mass()},
          {"area",adaptive_area.Mass()},{"center_of_mass",xyz(adaptive_mass.CentreOfMass())},
          {"estimated_volume_error",volume_error},{"estimated_area_error",area_error}});
    }
    for(double eps:{1e-6,1e-8,1e-10}){
        GProp_GProps kronrod;
        double error=BRepGProp::VolumePropertiesGK(shape,kronrod,eps,false,true,true,false,false);
        integrals.push_back({{"method","gauss_kronrod_split_spans"},{"eps",eps},{"volume",kronrod.Mass()},
            {"center_of_mass",xyz(kronrod.CentreOfMass())},{"estimated_volume_error",error}});
    }
    result["integration_probe"]=integrals;
    json states=json::array(),distances=json::array();
    for(auto& p:request.value("classify",json::array())){BRepClass3d_SolidClassifier classifier(shape,point(p),1e-8);auto state=classifier.State();states.push_back(state==TopAbs_IN?"inside":state==TopAbs_OUT?"outside":state==TopAbs_ON?"boundary":"unknown");}
    for(auto& p:request.value("distance",json::array())){BRepExtrema_DistShapeShape distance(shape,BRepBuilderAPI_MakeVertex(point(p)).Vertex());if(!distance.IsDone())distances.push_back(nullptr);else distances.push_back(distance.Value());}
    result["classifications"]=states;result["distances"]=distances;
    if(request.contains("distance_to_boundary")){
        BRep_Builder builder;TopoDS_Compound boundary;builder.MakeCompound(boundary);
        for(TopExp_Explorer face(shape,TopAbs_FACE);face.More();face.Next())builder.Add(boundary,face.Current());
        json boundary_distances=json::array();
        for(auto& p:request.at("distance_to_boundary")){
            BRepExtrema_DistShapeShape d(boundary,BRepBuilderAPI_MakeVertex(point(p)).Vertex());
            boundary_distances.push_back(d.IsDone()?json(d.Value()):json(nullptr));
        }
        result["boundary_distances"]=boundary_distances;
    }
    if(request.value("edges",false)){
        TopTools_IndexedMapOfShape edges;TopExp::MapShapes(shape,TopAbs_EDGE,edges);json curves=json::array();
        for(int i=1;i<=edges.Extent();i++){
            auto edge=TopoDS::Edge(edges(i));if(BRep_Tool::Degenerated(edge))continue;
            BRepAdaptor_Curve curve(edge);double first=curve.FirstParameter(),last=curve.LastParameter();
            json points=json::array();for(int j=0;j<=8;j++)points.push_back(xyz(curve.Value(first+(last-first)*j/8.)));
            curves.push_back({{"points",points},{"length",GCPnts_AbscissaPoint::Length(curve,first,last,1e-10)}});
        }
        result["edges"]=curves;
    }
    if(request.value("mesh",false)){
        double deflection=request.value("deflection",.01);BRepMesh_IncrementalMesh mesher(shape,deflection,false,.25,false);
        json triangles=json::array();
        for(TopExp_Explorer faces(shape,TopAbs_FACE);faces.More();faces.Next()){
            auto face=TopoDS::Face(faces.Current());TopLoc_Location location;auto mesh=BRep_Tool::Triangulation(face,location);
            if(mesh.IsNull())throw std::runtime_error("Unmeshed face");
            for(int i=1;i<=mesh->NbTriangles();i++){
                int x,y,z;mesh->Triangle(i).Get(x,y,z);if(face.Orientation()==TopAbs_REVERSED)std::swap(y,z);
                gp_Pnt a=mesh->Node(x).Transformed(location.Transformation()),b=mesh->Node(y).Transformed(location.Transformation()),c=mesh->Node(z).Transformed(location.Transformation());
                // Singular poles can produce zero-area topological mesh records.
                // Export only actual surface triangles; the independent grader still rejects degeneracy.
                if(gp_Vec(a,b).Crossed(gp_Vec(a,c)).Magnitude()<1e-12)continue;
                triangles.push_back({xyz(a),xyz(b),xyz(c)});
                if(triangles.size()>100000)throw std::runtime_error("Mesh size limit");
            }
        }
        result["triangles"]=triangles;
    }
    return result;
}

static json pipeline_job(const json& job){
    std::map<std::string,TopoDS_Shape> shapes;
    for(auto& step:job.at("steps")){
        std::string op=step.at("op"),id=step.at("id");TopoDS_Shape shape;
        auto position=step.value("origin",json::array({0,0,0}));
        if(op=="box"){auto size=step.at("size");shape=BRepPrimAPI_MakeBox(point(position),size[0].get<double>(),size[1].get<double>(),size[2].get<double>()).Shape();}
        else if(op=="sphere")shape=BRepPrimAPI_MakeSphere(point(position),step.at("radius").get<double>()).Shape();
        else if(op=="cylinder")shape=BRepPrimAPI_MakeCylinder(axes(step),step.at("radius").get<double>(),step.at("height").get<double>()).Shape();
        else if(op=="cone")shape=BRepPrimAPI_MakeCone(axes(step),step.at("radius1").get<double>(),step.at("radius2").get<double>(),step.at("height").get<double>()).Shape();
        else if(op=="torus")shape=BRepPrimAPI_MakeTorus(axes(step),step.at("major").get<double>(),step.at("minor").get<double>()).Shape();
        else if(op=="prism")shape=BRepPrimAPI_MakePrism(polygon_face(step.at("profile")),vec(step.at("vector"))).Shape();
        else if(op=="revolve")shape=BRepPrimAPI_MakeRevol(polygon_face(step.at("profile")),gp_Ax1(point(position),gp_Dir(vec(step.at("axis")))),step.at("angle").get<double>()).Shape();
        else if(op=="loft"){
            BRepOffsetAPI_ThruSections loft(true,step.value("ruled",false),1e-7);
            for(auto& profile:step.at("profiles")){
                BRepBuilderAPI_MakePolygon wire;for(auto& p:profile)wire.Add(point(p));wire.Close();loft.AddWire(wire.Wire());
            }
            loft.Build();if(!loft.IsDone())throw std::runtime_error("Loft failed");shape=loft.Shape();
        }else if(op=="sweep"){
            auto curve=make_curve(step.at("path"));auto interval=step.at("path_interval");
            auto edge=BRepBuilderAPI_MakeEdge(curve,interval[0].get<double>(),interval[1].get<double>()).Edge();
            const auto& profile=step.at("profile");
            if(profile.contains("holes")&&!profile.at("holes").empty())throw std::runtime_error("This author probe does not cover holes");
            BRepOffsetAPI_MakePipeShell sweep(BRepBuilderAPI_MakeWire(edge).Wire());
            sweep.SetMode(false);
            sweep.SetTolerance(1e-9,1e-9,1e-9);
            sweep.SetMaxDegree(12);sweep.SetMaxSegments(256);
            sweep.Add(BRepTools::OuterWire(polygon_face(profile)),false,false);
            sweep.Build();if(!sweep.IsDone()||!sweep.MakeSolid())throw std::runtime_error("Precision sweep failed");shape=sweep.Shape();
        }else if(op=="fillet"){
            auto source=shapes.at(step.at("source"));BRepFilletAPI_MakeFillet fillet(source);
            TopTools_IndexedMapOfShape edges;TopExp::MapShapes(source,TopAbs_EDGE,edges);
            for(int i=1;i<=edges.Extent();i++){
                auto edge=TopoDS::Edge(edges(i));if(BRep_Tool::Degenerated(edge))continue;
                BRepAdaptor_Curve c(edge);auto midpoint=c.Value((c.FirstParameter()+c.LastParameter())/2);
                bool selected=true;
                if(step.contains("midpoint_bounds")){
                    auto bounds=step.at("midpoint_bounds");auto q=xyz(midpoint);
                    for(int j=0;j<3;j++)if(q[j].get<double>()<bounds[0][j].get<double>()-1e-8||q[j].get<double>()>bounds[1][j].get<double>()+1e-8)selected=false;
                }
                if(selected)fillet.Add(step.at("radius").get<double>(),edge);
            }
            fillet.Build();if(!fillet.IsDone())throw std::runtime_error("Fillet failed");shape=fillet.Shape();
        }else if(op=="offset"){
            BRepOffsetAPI_MakeOffsetShape offset;
            offset.PerformByJoin(shapes.at(step.at("source")),step.at("distance").get<double>(),1e-7,BRepOffset_Skin,false,false,GeomAbs_Arc,true);
            if(!offset.IsDone())throw std::runtime_error("Offset failed");shape=offset.Shape();
        }else if(op=="union")shape=BRepAlgoAPI_Fuse(shapes.at(step.at("a")),shapes.at(step.at("b"))).Shape();
        else if(op=="cut")shape=BRepAlgoAPI_Cut(shapes.at(step.at("a")),shapes.at(step.at("b"))).Shape();
        else if(op=="common")shape=BRepAlgoAPI_Common(shapes.at(step.at("a")),shapes.at(step.at("b"))).Shape();
        else if(op=="section")shape=BRepAlgoAPI_Section(shapes.at(step.at("a")),shapes.at(step.at("b"))).Shape();
        else if(op=="transform"){
            gp_Trsf transform;
            if(step.contains("translation"))transform.SetTranslation(vec(step.at("translation")));
            else if(step.contains("scale"))transform.SetScale(point(position),step.at("scale").get<double>());
            else transform.SetRotation(gp_Ax1(point(position),gp_Dir(vec(step.at("axis")))),step.at("angle").get<double>());
            shape=BRepBuilderAPI_Transform(shapes.at(step.at("source")),transform,true).Shape();
        }else if(op=="repair"){
            Handle(ShapeFix_Shape) fixer=new ShapeFix_Shape(shapes.at(step.at("source")));
            fixer->SetPrecision(step.value("tolerance",1e-7));fixer->Perform();shape=fixer->Shape();
        }else if(op=="simplify"){
            ShapeUpgrade_UnifySameDomain unify(shapes.at(step.at("source")),true,true,true);unify.Build();shape=unify.Shape();
        }else if(op=="sew"){
            BRepBuilderAPI_Sewing sew(step.value("tolerance",1e-7));
            for(auto& profile:step.at("faces"))sew.Add(polygon_face(profile));sew.Perform();shape=sew.SewedShape();
            if(step.value("solid",false)){
                if(shape.ShapeType()!=TopAbs_SHELL)throw std::runtime_error("Sew did not produce one shell");
                auto solid=BRepBuilderAPI_MakeSolid(TopoDS::Shell(shape)).Solid();
                if(!BRepLib::OrientClosedSolid(solid))throw std::runtime_error("Sewn solid not closed");shape=solid;
            }
        }else throw std::runtime_error("Unsupported shape step");
        if(shape.IsNull())throw std::runtime_error("Null shape");shapes[id]=shape;
    }
    json result=json::array();
    for(auto& observation:job.at("observe"))result.push_back(shape_observation(shapes.at(observation.at("id")),observation));
    return {{"ok",true},{"results",result}};
}

int main(){
    json input;std::cin>>input;json results=json::array();
    for(auto& request:input.at("cases")){
        try{
            std::string kind=request.at("op");
            results.push_back(kind=="curve"?curve_job(request):kind=="surface"?surface_job(request):kind=="pipeline"?pipeline_job(request):json({{"ok",false}}));
        }catch(const Standard_Failure&){results.push_back({{"ok",false}});}
         catch(const std::exception&){results.push_back({{"ok",false}});}
    }
    std::cout<<json({{"results",results}}).dump()<<"\n";
}
