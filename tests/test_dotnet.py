"""ASP.NET Core rules: structural positives, security-preserving decoys, project-local context and privacy."""
import json
import os
import shutil
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path

import _util
from jh_core import source_from_text
from jh_rules import ScanOptions, scan_sources

IDS = {'JH%d' % i for i in range(135,144)}


def scan(files, ids=IDS):
    sources = [source_from_text(p, '/fixture/'+p, t) for p,t in files.items()]
    return scan_sources([s for s in sources if s], ScanOptions(rule_ids=ids)).findings


def found(text, rid, name='Program.cs'):
    return [f for f in scan({name:text}, {rid}) if f.rule==rid]


class Authorization(unittest.TestCase):
    def test_malformed_endpoint_volume_finishes_without_rescanning(self):
        script = '''import sys
sys.path.insert(0, sys.argv[1])
from jh_core import source_from_text
from jh_rules import RULES
import jh_dotnet
source = source_from_text("Program.cs", "/fixture/Program.cs", "app.MapGet(" * 25000)
rule = next(r for r in RULES if r.id == "JH135")
assert jh_dotnet.findings(source, rule, {}) == []
'''
        result = subprocess.run([sys.executable, '-c', script, _util.SCRIPTS],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_private_minimal_endpoint_and_safe_health(self):
        code = 'var app = WebApplication.CreateBuilder(args).Build();\n' \
               'app.MapGet("/users", (Db db) => Results.Ok(db.Users));\n' \
               'app.MapPost("/orders", async (Db db) => { await db.SaveChangesAsync(); return Results.Ok(); });\n' \
               'app.MapGet("/health", () => Results.Ok(new {status="ok"}));\n'
        self.assertEqual([f.line for f in found(code,'JH135')],[2,3])

    def test_explicit_group_and_global_authorization(self):
        for text in [
            'app.MapGet("/users", (Db db)=>Results.Ok(db.Users)).RequireAuthorization();',
            'var api=app.MapGroup("/api").RequireAuthorization(); api.MapGet("/users", (Db db)=>Results.Ok(db.Users));',
            'var api=app.MapGroup("/api").RequireAuthorization(); var child=api.MapGroup("/v1"); child.MapGet("/users", (Db db)=>db.Users);',
            'var route=app.MapGet("/users", (Db db)=>Results.Ok(db.Users)); route.RequireAuthorization();',
            'app.MapGet("/users", (Db db)=>Results.Ok(db.Users)).WithMetadata(new AuthorizeAttribute());',
            'builder.Services.AddAuthorization(o=>o.FallbackPolicy=new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());\n'
            'app.MapGet("/users", (Db db)=>Results.Ok(db.Users));']:
            self.assertEqual(found(text,'JH135'),[],text)
        code='var api=app.MapGroup("/api").RequireAuthorization(); api.MapGet("/users", (Db db)=>Results.Ok(db.Users)).AllowAnonymous();'
        self.assertEqual(len(found(code,'JH135')),1)
        self.assertEqual(len(found('var route=app.MapGet("/users", (Db db)=>Results.Ok(db.Users)).RequireAuthorization(); route.AllowAnonymous();','JH135')),1)
        self.assertEqual(len(found('var api=app.MapGroup("/api").RequireAuthorization(); api=app.MapGroup("/public"); api.MapGet("/users",(Db db)=>db.Users);','JH135')),1)

    def test_reassigned_parent_and_conditional_authorization_are_not_inherited(self):
        endpoint='child.MapGet("/users", (Db db)=>Results.Ok(db.Users));'
        code='var api=app.MapGroup("/private").RequireAuthorization(); api=app.MapGroup("/public"); var child=api.MapGroup("/v1"); '+endpoint
        self.assertEqual(len(found(code,'JH135')),1)
        code='var child=app.MapGroup("/api"); if(app.Environment.IsDevelopment()) child.RequireAuthorization(); '+endpoint
        self.assertEqual(len(found(code,'JH135')),1)
        self.assertEqual(found(code.replace('IsDevelopment())','IsDevelopment() == false)'),'JH135'),[])

    def test_controllers_attributes_and_anonymous_override(self):
        controller='[ApiController]\n%s\npublic class UsersController : ControllerBase {\n%s\n[HttpGet("users")]\npublic IActionResult Users()=>Ok(users);\n}'
        self.assertEqual(len(found(controller%('',''),'JH135')),1)
        self.assertEqual(found(controller%('[Authorize]',''),'JH135'),[])
        self.assertEqual(len(found(controller%('[Authorize]','[AllowAnonymous]'),'JH135')),1)
        self.assertEqual(found(controller%('','[Authorize]'),'JH135'),[])
        self.assertEqual(found((controller%('','')).replace('[HttpGet("users")]','[HttpGet("users"), Authorize]'),'JH135'),[])
        safe='[ApiController] public class PublicController:ControllerBase { [HttpGet("metrics")] public IActionResult Metrics()=>Ok(new {cpu=42,mem=68}); }'
        self.assertEqual(found(safe,'JH135'),[])

    def test_controller_brace_style_and_action_boundaries(self):
        code='''[ApiController]
public class PatientsController : ControllerBase
{
    [HttpGet("patients")]
    public IActionResult Read()
    {
        return Ok(patients);
    }
    [HttpGet("health")]
    public IActionResult Health() => Ok(new { status = "ok" });
    [HttpPost("patients")]
    public IActionResult Acknowledge([FromBody] Input input) => Ok(new { accepted = true });
}'''
        self.assertEqual([f.line for f in found(code,'JH135')],[4])
        self.assertEqual(found(code.replace('[ApiController]','[ApiController, Authorize]'),'JH135'),[])

    def test_fallback_does_not_cross_projects_or_come_from_a_comment(self):
        files={'one/a.csproj':'<Project/>','one/Auth.cs':'builder.Services.AddAuthorization(o=>o.FallbackPolicy=new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());',
               'two/b.csproj':'<Project/>','two/Program.cs':'app.MapGet("/users", (Db db)=>Results.Ok(db.Users));'}
        self.assertEqual([f.path for f in scan(files,{'JH135'})],['two/Program.cs'])
        text='// FallbackPolicy=new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();\napp.MapGet("/users", (Db db)=>Results.Ok(db.Users));'
        self.assertEqual(len(found(text,'JH135')),1)
        text='if(false){ options.FallbackPolicy=new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build(); }\napp.MapGet("/users", (Db db)=>Results.Ok(db.Users));'
        self.assertEqual(len(found(text,'JH135')),1)
        text='if(enabled){ Log.Info("start"); } builder.Services.AddAuthorization(o=>o.FallbackPolicy=new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());\napp.MapGet("/users", (Db db)=>Results.Ok(db.Users));'
        self.assertEqual(found(text,'JH135'),[])


class Structural(unittest.TestCase):
    def test_cors_policies_stay_separate(self):
        for text in ['app.UseCors(p=>p.AllowAnyOrigin().AllowCredentials());',
                     'app.UseCors(p=>p.AllowCredentials().AllowAnyOrigin());',
                     'app.UseCors(p=>p.SetIsOriginAllowed(_=>true).AllowCredentials());']:
            self.assertEqual(len(found(text,'JH136')),1,text)
        for text in ['app.UseCors(p=>p.AllowAnyOrigin());',
                     'app.UseCors(p=>p.WithOrigins("https://app.example.invalid").AllowCredentials());',
                     'options.AddPolicy("public",p=>p.AllowAnyOrigin()); options.AddPolicy("private",p=>p.WithOrigins("https://x.invalid").AllowCredentials());',
                     'app.UseCors(p=>p.SetIsOriginAllowed(o=>allowed.Contains(o)).AllowCredentials());']:
            self.assertEqual(found(text,'JH136'),[],text)

    def test_environment_guard_scope(self):
        for text in ['if(app.Environment.IsDevelopment()){app.UseDeveloperExceptionPage();}',
                     'if(builder.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();',
                     'if(app.Environment.IsDevelopment() == true) app.UseDeveloperExceptionPage();',
                     'if(false != app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();',
                     'if(enabled && app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();',
                     'if(!app.Environment.IsDevelopment()) { app.UseExceptionHandler(); } else { app.UseDeveloperExceptionPage(); }',
                     'if(app.Environment.EnvironmentName == "Development") app.UseDeveloperExceptionPage();']:
            self.assertEqual(found(text,'JH137'),[],text)
        for text in ['app.UseDeveloperExceptionPage();',
                     'if(app.Environment.IsDevelopment()) { Console.WriteLine("dev"); } app.UseDeveloperExceptionPage();',
                     'if(!app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();',
                     'if(!(app.Environment.IsDevelopment())) app.UseDeveloperExceptionPage();',
                     'if(app.Environment.IsDevelopment() || enabled) app.UseDeveloperExceptionPage();',
                     'if(app.Environment.IsDevelopment() == false) app.UseDeveloperExceptionPage();',
                     'if(false == app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();',
                     'if(app.Environment.IsDevelopment() is false) app.UseDeveloperExceptionPage();',
                     'if(app.Environment.IsDevelopment() is not true) app.UseDeveloperExceptionPage();',
                     'if(app.Environment.IsDevelopment() == enabled) app.UseDeveloperExceptionPage();']:
            self.assertEqual(len(found(text,'JH137')),1,text)

    def test_kestrel_and_project_local_redirection(self):
        for text in ['builder.WebHost.UseUrls("http://0.0.0.0:5000");','options.ListenAnyIP(5000);']:
            self.assertEqual(len(found(text,'JH138')),1)
        for text in ['options.ListenAnyIP(5000, o=>o.UseHttps());',
                     'builder.WebHost.UseUrls("http://127.0.0.1:5000");',
                     'builder.WebHost.UseUrls("http://*:5000"); app.UseHttpsRedirection();']:
            self.assertEqual(found(text,'JH138'),[],text)
        files={'a.csproj':'<Project/>','Program.cs':'app.UseHttpsRedirection();',
               'appsettings.json':'{"urls":"http://0.0.0.0:5000"}'}
        self.assertEqual(scan(files,{'JH138'}),[])
        self.assertEqual(found('{"urls":"http://0.0.0.0:5000"}','JH138','appsettings.Development.json'),[])
        self.assertEqual(found('{"ExternalClient":{"Url":"http://0.0.0.0:5000"}}','JH138','appsettings.json'),[])
        self.assertEqual(len(found('{"Kestrel":{"Endpoints":{"Http":{"Url":"http://*:5000"}}}}','JH138','appsettings.Production.json')),1)

    def test_development_only_https_is_not_a_production_control(self):
        listener='builder.WebHost.UseUrls("http://*:5000");'
        for guard in ['app.Environment.IsDevelopment()', 'enabled', 'false', '!app.Environment.IsDevelopment() && enabled']:
            code='if('+guard+') app.UseHttpsRedirection(); '+listener
            self.assertEqual(len(found(code,'JH138')),1,guard)
        for guard in ['!app.Environment.IsDevelopment()', 'app.Environment.IsDevelopment() == false', 'true']:
            code='if('+guard+') { app.UseHttpsRedirection(); } '+listener
            self.assertEqual(found(code,'JH138'),[],guard)
        code='if(app.Environment.IsDevelopment()) { Log.Info("dev"); } else { app.UseHttpsRedirection(); } '+listener
        self.assertEqual(found(code,'JH138'),[])

    def test_sql_interpolation_is_not_parameterization(self):
        for text in ['db.Users.FromSqlRaw($"SELECT * FROM users WHERE name=\'{name}\'");',
                     'var sql=$"SELECT * FROM users WHERE name=\'{name}\'"; conn.QueryAsync<dynamic>(sql);',
                     'new SqlCommand($"DELETE FROM users WHERE id={id}", connection);']:
            self.assertEqual(len(found(text,'JH139')),1,text)
        self.assertEqual(len(found('cmd.CommandText=$"SELECT * FROM users WHERE name=\'{name}\'";','JH139')),1)
        for text in ['db.Users.FromSqlInterpolated($"SELECT * FROM users WHERE id={id}");',
                     'db.Users.FromSql($"SELECT * FROM users WHERE id={id}");',
                     'db.Users.FromSqlRaw("SELECT * FROM users WHERE id={0}", id);',
                     'conn.QueryAsync("SELECT * FROM users WHERE id=@id", new {id});',
                     'string example=$"SELECT * FROM users WHERE id={id}"; Console.WriteLine(example);']:
            self.assertEqual(found(text,'JH139'),[],text)

    def test_type_metadata_requires_a_deserialization_use(self):
        text='var s=new JsonSerializerSettings {TypeNameHandling=TypeNameHandling.All}; var data=JsonConvert.DeserializeObject<object>(body,s);'
        self.assertEqual(len(found(text,'JH140')),1)
        self.assertEqual(found(text.replace('TypeNameHandling.All','TypeNameHandling.None'),'JH140'),[])
        self.assertEqual(found(text.replace('DeserializeObject<object>','SerializeObject'),'JH140'),[])
        self.assertEqual(found(text.replace('TypeNameHandling=','SerializationBinder=new KnownTypesBinder(), TypeNameHandling='),'JH140'),[])
        unrelated='var outbound=new JsonSerializerSettings {TypeNameHandling=TypeNameHandling.All}; JsonConvert.SerializeObject(data,outbound); JsonConvert.DeserializeObject<Dto>(body);'
        self.assertEqual(found(unrelated,'JH140'),[])

    def test_ai_client_personal_fields_and_explicit_redaction(self):
        text='builder.Services.AddHttpClient<Summariser>(c=>c.BaseAddress=new Uri("https://ai-gateway.corp.internal/"));\n'
        text+='app.MapPost("/intake", (Summariser ai, Form body)=>ai.Summarise(body.Name,body.Email,body.Message));'
        self.assertEqual(len(found(text,'JH141')),1)
        self.assertEqual(found(text.replace('body.Email','Redact(body.Email)'),'JH141'),[])
        self.assertEqual(len(found(text.replace('body.Email','Sanitize(body.Email)'),'JH141')),1)
        self.assertEqual(len(found(text.replace('body.Message','Sanitize(body.Message)'),'JH141')),1)
        self.assertEqual(found('client.PostAsJsonAsync("https://api.example.invalid/notify", new { input.Email });','JH141'),[])
        self.assertEqual(found('client.PostAsJsonAsync("https://api.openai.com/v1/chat/completions", new { prompt="body.Email" });','JH141'),[])
        self.assertEqual(len(found('client.PostAsJsonAsync("https://api.openai.com/v1/chat/completions", new { body.Email });','JH141')),1)

    def test_xml_versions_exec_and_comment_decoys(self):
        xml='<Project><ItemGroup><PackageReference Include="Dapper" Version="*"/></ItemGroup><Target Name="x"><Exec Command="curl https://config.example.invalid/x -o x"/></Target></Project>'
        self.assertEqual(len(found(xml,'JH142','app.csproj')),1)
        self.assertEqual(len(found(xml,'JH143','app.csproj')),1)
        self.assertEqual(found(xml.replace('Version="*"','Version="2.1.0"'),'JH142','app.csproj'),[])
        self.assertEqual(found('<Project><!--'+xml+'</Project>--></Project>','JH142','app.csproj'),[])
        self.assertEqual(found('<Project><Target Name="x"><Exec Command="dotnet --info"/></Target></Project>','JH143','app.csproj'),[])

    def test_comments_strings_and_evidence_credentials(self):
        text='// app.UseDeveloperExceptionPage();\nvar doc="app.UseDeveloperExceptionPage();";'
        self.assertEqual(found(text,'JH137'),[])
        secret='Wq7Lm2'+'Xz9Rb4'
        xml='<Project><Target Name="x"><Exec Command="curl https://user:'+secret+'@config.example.invalid/file -o file"/></Target></Project>'
        f=found(xml,'JH143','app.csproj')[0]
        self.assertNotIn(secret,f.evidence)
        self.assertEqual(found('<!DOCTYPE Project [<!ENTITY x SYSTEM "file:///etc/passwd">]><Project>&x;</Project>','JH143','x.csproj'),[])


class Citizen(unittest.TestCase):
    def test_authorization_is_a_citizen_governance_lead(self):
        root=tempfile.mkdtemp(prefix='jh-dotnet-')
        self.addCleanup(shutil.rmtree,root,True)
        Path(root,'app.csproj').write_text('<Project/>')
        Path(root,'Program.cs').write_text('app.MapGet("/users", (Db db)=>Results.Ok(db.Users));')
        p=_util.run_cli('passport',root,'--profile','citizen','--json')
        d=json.loads(p.stdout)
        self.assertIn('P-SEC-001',[r['rule'] for r in d['assessment']['decision']['reasons']])
        p=_util.run_cli('passport',root,'--profile','citizen','--json','--ignore-rule','JH135')
        self.assertNotIn('JH135',[x['rule'] for x in json.loads(p.stdout)['governance']['top_problems']])


if __name__=='__main__':unittest.main()
